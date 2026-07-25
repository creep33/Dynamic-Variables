package burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class VariableHttpHandler implements HttpHandler {
    private final MontoyaApi api;
    private final VariableManager variableManager;
    private final Map<Integer, RequestTrace> requestTraces = new ConcurrentHashMap<>();
    private final LatestRequestTracker latestRequests = new LatestRequestTracker();

    public VariableHttpHandler(MontoyaApi api, VariableManager variableManager) {
        this.api = api;
        this.variableManager = variableManager;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        if (request.toolSource().isFromTool(ToolType.EXTENSIONS)) {
            return RequestToBeSentAction.continueWith(request);
        }

        AutomationTool tool = AutomationTool.from(request.toolSource());
        if (tool == null) return RequestToBeSentAction.continueWith(request);

        HttpRequest finalRequest = request;
        HttpRequest originalTemplate = null;
        Set<String> variablesUsed = Set.of();
        VariableNames.PlaceholderStyle placeholderStyle = variableManager.getPlaceholderStyle();

        if (isReplacementEnabled(request)) {
            Map<String, String> variables = variableManager.getVariables();
            if (!variables.isEmpty()) {
                HttpRewriteResult rewrite = rewriteRequest(request, variables, placeholderStyle);
                variablesUsed = Set.copyOf(rewrite.variablesUsed());
                if (!variablesUsed.isEmpty()) {
                    originalTemplate = HttpRequest.httpRequest(request.httpService(), request.toByteArray());
                    finalRequest = rewrite.request();
                }
            }
        }

        Map<String, Long> extractionSequences = registerExtractionCandidates(finalRequest, tool);
        requestTraces.put(request.messageId(), new RequestTrace(
                originalTemplate, variablesUsed, placeholderStyle, tool, extractionSequences));

        return finalRequest == request
                ? RequestToBeSentAction.continueWith(request)
                : RequestToBeSentAction.continueWith(finalRequest);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response) {
        int messageId = response.messageId();
        RequestTrace trace = requestTraces.remove(messageId);
        if (response.toolSource().isFromTool(ToolType.EXTENSIONS)) {
            return ResponseReceivedAction.continueWith(response);
        }

        AutomationTool tool = trace == null ? AutomationTool.from(response.toolSource()) : trace.tool();
        HttpRequest initiatingRequest = response.initiatingRequest();
        if (tool != null && initiatingRequest != null) {
            runPassiveExtraction(messageId, tool, trace, initiatingRequest,
                    response.statusCode(), response.headers(), response.bodyToString());
        }

        if (trace == null || tool == null) return ResponseReceivedAction.continueWith(response);
        return recoverSessionIfAuthorized(response, trace);
    }

    private Map<String, Long> registerExtractionCandidates(HttpRequest request, AutomationTool tool) {
        if (!variableManager.isExtractionEnabled()) return Map.of();
        if (!variableManager.isExtractionToolEnabled(tool)) return Map.of();

        Map<String, VariableExtractionRule> rules = variableManager.getRules();
        Map<String, String> variables = variableManager.getVariables();
        ExtractionEngine.RequestSnapshot snapshot = snapshot(request);
        Map<String, Long> candidates = new LinkedHashMap<>();
        for (Map.Entry<String, VariableExtractionRule> entry : rules.entrySet()) {
            if (!entry.getValue().isEnabled()) continue;
            ExtractionOutcome mismatch = requestMismatch(request, snapshot, entry.getValue(), variables);
            if (mismatch != null) continue;
            long candidateSequence = latestRequests.register(entry.getKey());
            candidates.put(entry.getKey(), candidateSequence);
        }
        return Map.copyOf(candidates);
    }

    private void runPassiveExtraction(int messageId, AutomationTool tool, RequestTrace trace,
                                      HttpRequest request, int responseStatusCode,
                                      List<HttpHeader> responseHeaders, String responseBody) {
        if (!variableManager.isExtractionEnabled()) {
            debug(messageId, null, ExtractionOutcome.GLOBAL_DISABLED);
            return;
        }
        if (!variableManager.isExtractionToolEnabled(tool)) {
            debug(messageId, null, ExtractionOutcome.TOOL_DISABLED);
            return;
        }
        if (trace == null || trace.extractionSequences().isEmpty()) return;

        Map<String, VariableExtractionRule> rules = variableManager.getRules();
        Map<String, String> variables = variableManager.getVariables();
        ExtractionEngine.RequestSnapshot requestSnapshot = snapshot(request);
        ExtractionEngine.ResponseSnapshot responseSnapshot = new ExtractionEngine.ResponseSnapshot(
                responseStatusCode, headerLines(responseHeaders), responseBody);
        Map<String, VariableExtractionRule> matched = new LinkedHashMap<>();
        Set<String> contexts = new LinkedHashSet<>();

        for (Map.Entry<String, Long> candidate : trace.extractionSequences().entrySet()) {
            String variable = candidate.getKey();
            VariableExtractionRule rule = rules.get(variable);
            if (rule == null || !rule.isEnabled()) {
                debug(messageId, variable, ExtractionOutcome.RULE_DISABLED);
                continue;
            }
            if (!latestRequests.isLatest(variable, candidate.getValue())) {
                debug(messageId, variable, ExtractionOutcome.STALE_RESPONSE);
                continue;
            }
            ExtractionOutcome mismatch = requestMismatch(request, requestSnapshot, rule, variables);
            if (mismatch != null) {
                debug(messageId, variable, mismatch);
                continue;
            }
            matched.put(variable, rule);
            contexts.add(variableManager.getVariableContext(variable));
        }

        if (!AutomationPolicy.isSingleContext(contexts)) {
            for (String variable : matched.keySet()) {
                debug(messageId, variable, ExtractionOutcome.AMBIGUOUS_CONTEXT);
            }
            return;
        }

        Map<String, String> updates = new LinkedHashMap<>();
        for (Map.Entry<String, VariableExtractionRule> entry : matched.entrySet()) {
            ExtractionEngine.Evaluation evaluation = ExtractionEngine.extract(
                    entry.getValue(), requestSnapshot, responseSnapshot);
            if (evaluation.outcome() == ExtractionOutcome.UPDATED && evaluation.value() != null) {
                updates.put(entry.getKey(), evaluation.value());
            } else {
                debug(messageId, entry.getKey(), evaluation.outcome());
                if (evaluation.outcome() == ExtractionOutcome.INVALID_REGEX
                        || evaluation.outcome() == ExtractionOutcome.INVALID_TEMPLATE
                        || evaluation.outcome() == ExtractionOutcome.MISSING_CAPTURE_GROUP) {
                    api.logging().logToError("[DynamicVariables][AutoExtraction] message=" + messageId
                            + " variable=\"" + entry.getKey() + "\" result=" + evaluation.outcome());
                }
            }
        }
        if (!updates.isEmpty()) {
            Map<String, String> oldValues = variableManager.getVariables();
            variableManager.updateVariableValues(updates);
            for (Map.Entry<String, String> update : updates.entrySet()) {
                int oldLength = oldValues.getOrDefault(update.getKey(), "").length();
                api.logging().logToOutput("[DynamicVariables][AutoExtraction] message=" + messageId
                        + " variable=\"" + update.getKey() + "\" result=UPDATED oldLength="
                        + oldLength + " newLength=" + update.getValue().length());
            }
        }
    }

    private ResponseReceivedAction recoverSessionIfAuthorized(HttpResponseReceived response, RequestTrace trace) {
        boolean globalEnabled = variableManager.isSessionRecoveryEnabled();
        boolean toolEnabled = variableManager.isRecoveryToolEnabled(trace.tool());
        boolean hasTemplate = trace.originalTemplate() != null;
        boolean hasVariables = !trace.variablesUsed().isEmpty();

        // The refresh candidates are resolved first because expiry signals live on the rules.
        Map<String, VariableExtractionRule> allRules = variableManager.getRules();
        Map<String, VariableExtractionRule> refreshRules = new LinkedHashMap<>();
        for (String variable : trace.variablesUsed()) {
            VariableExtractionRule rule = allRules.get(variable);
            if (AutomationPolicy.isRefreshCandidate(rule)) {
                refreshRules.put(variable, rule);
            }
        }
        ExtractionEngine.ResponseSnapshot responseSnapshot = new ExtractionEngine.ResponseSnapshot(
                response.statusCode(), headerLines(response.headers()), response.bodyToString());
        boolean configuredStatus = expiryDetected(
                response.messageId(), refreshRules, responseSnapshot);

        if (!AutomationPolicy.canAttemptRecovery(
                globalEnabled, toolEnabled, configuredStatus, hasTemplate, hasVariables)) {
            if (globalEnabled && !toolEnabled) {
                debug(response.messageId(), null, ExtractionOutcome.TOOL_DISABLED);
            }
            return ResponseReceivedAction.continueWith(response);
        }
        if (refreshRules.isEmpty()) {
            debug(response.messageId(), null, ExtractionOutcome.NO_REFRESH_CANDIDATE);
            return ResponseReceivedAction.continueWith(response);
        }

        String method = trace.originalTemplate().method().toUpperCase();
        if (!AutomationPolicy.isReplayAuthorized(method, refreshRules.values())) {
            debug(response.messageId(), null, ExtractionOutcome.UNSAFE_REPLAY_DISABLED);
            return ResponseReceivedAction.continueWith(response);
        }

        StagedRefreshCoordinator.Result staged = StagedRefreshCoordinator.stage(
                refreshRules, variableManager.getVariables(),
                variableManager::fetchRefreshedVariable);
        if (!staged.successful()) {
            api.logging().logToError("[DynamicVariables][SessionRecovery] message="
                    + response.messageId() + " result=REFRESH_FAILED error=" + safeError(staged.error()));
            return continueOriginalWithNote(response,
                    "Dynamic Variables: automatic recovery failed; original HTTP "
                            + response.statusCode() + " preserved.");
        }
        Map<String, String> stagedValues = staged.values();

        Map<String, String> refreshedVariables = variableManager.getVariables();
        refreshedVariables.putAll(stagedValues);
        HttpRequest retriedRequest = rewriteRequest(
                trace.originalTemplate(), refreshedVariables, trace.placeholderStyle()).request();
        try {
            HttpRequestResponse retried = api.http().sendRequest(retriedRequest);
            if (retried.response() == null) {
                return continueOriginalWithNote(response,
                        "Dynamic Variables: retry returned no response; original HTTP "
                                + response.statusCode() + " preserved.");
            }
            variableManager.updateVariableValues(stagedValues);
            String note = "Dynamic Variables: automatic session recovery for message "
                    + response.messageId() + " (" + trace.tool() + "); original HTTP "
                    + response.statusCode() + ", retry HTTP " + retried.response().statusCode() + ".";
            api.logging().logToOutput("[DynamicVariables][SessionRecovery] message="
                    + response.messageId() + " tool=" + trace.tool() + " originalStatus="
                    + response.statusCode() + " retryStatus=" + retried.response().statusCode()
                    + " result=COMPLETED");
            return ResponseReceivedAction.continueWith(
                    retried.response(), appendNote(response.annotations(), note));
        } catch (Exception error) {
            api.logging().logToError("[DynamicVariables][SessionRecovery] message="
                    + response.messageId() + " result=REPLAY_FAILED error=" + safeError(error));
            return continueOriginalWithNote(response,
                    "Dynamic Variables: retry failed; original HTTP "
                            + response.statusCode() + " preserved.");
        }
    }

    /**
     * A rule may describe how its own application announces an expired session (for example a
     * 302 carrying {@code Location: /login}). When no rule involved in this transaction supplies
     * a usable signal, the globally configured refresh status codes decide, which is what every
     * rule created before this feature relies on.
     */
    private boolean expiryDetected(int messageId, Map<String, VariableExtractionRule> refreshRules,
                                   ExtractionEngine.ResponseSnapshot responseSnapshot) {
        boolean anyUsableSignal = false;
        for (Map.Entry<String, VariableExtractionRule> entry : refreshRules.entrySet()) {
            VariableExtractionRule.ExpirySignal signal = entry.getValue().getExpirySignal();
            if (signal == null) continue;
            if (!AutomationPolicy.isExpirySignalUsable(signal)) {
                debug(messageId, entry.getKey(), ExtractionOutcome.EXPIRY_SIGNAL_UNUSABLE);
                continue;
            }
            anyUsableSignal = true;
            ExtractionOutcome outcome = ExtractionEngine.matchesExpirySignal(signal, responseSnapshot);
            if (outcome == null) return true;
            debug(messageId, entry.getKey(), outcome);
        }
        if (anyUsableSignal) return false;
        return variableManager.getRefreshStatusCodes().contains(responseSnapshot.statusCode());
    }

    private ResponseReceivedAction continueOriginalWithNote(HttpResponseReceived response, String note) {
        return ResponseReceivedAction.continueWith(response, appendNote(response.annotations(), note));
    }

    private Annotations appendNote(Annotations existing, String note) {
        String current = existing != null && existing.hasNotes() ? existing.notes() : "";
        String combined = current.isBlank() ? note : current + "\n" + note;
        return existing == null ? Annotations.annotations(combined) : existing.withNotes(combined);
    }

    private ExtractionOutcome requestMismatch(HttpRequest actualRequest,
                                              ExtractionEngine.RequestSnapshot snapshot,
                                              VariableExtractionRule rule,
                                              Map<String, String> variables) {
        if (rule.getMatchStrategy() == VariableExtractionRule.MatchStrategy.EXPLICIT) {
            return ExtractionEngine.matchesExplicitRequest(rule, snapshot);
        }
        if (!legacyPathMatches(rule, actualRequest.path())) return ExtractionOutcome.PATH_MISMATCH;
        if (rule.getMatchStrategy() == VariableExtractionRule.MatchStrategy.LEGACY_EXACT
                && !matchesSavedRequest(actualRequest, rule, variables)) {
            return ExtractionOutcome.LEGACY_REQUEST_MISMATCH;
        }
        return null;
    }

    private boolean legacyPathMatches(VariableExtractionRule rule, String path) {
        if (rule.getMatchUrl() == null || rule.getMatchUrl().isEmpty()) return true;
        try {
            return Pattern.compile(rule.getMatchUrl()).matcher(path).find();
        } catch (PatternSyntaxException error) {
            return false;
        }
    }

    private boolean matchesSavedRequest(HttpRequest actualRequest, VariableExtractionRule rule,
                                        Map<String, String> variables) {
        try {
            HttpRequest expectedRequest = HttpRequest.httpRequest(ByteArray.byteArray(
                    Base64.getDecoder().decode(rule.getSavedRequestBase64())));
            if (!expectedRequest.method().equalsIgnoreCase(actualRequest.method())) return false;
            HttpService actualService = actualRequest.httpService();
            if (actualService == null
                    || !rule.getSavedHost().equalsIgnoreCase(actualService.host())
                    || rule.getSavedPort() != actualService.port()
                    || rule.isSavedSecure() != actualService.secure()) return false;
            if (!replacePlaceholders(expectedRequest.path(), variables).equals(actualRequest.path())) return false;
            if (!nullToEmpty(replacePlaceholders(expectedRequest.bodyToString(), variables))
                    .equals(nullToEmpty(actualRequest.bodyToString()))) return false;
            for (HttpHeader expectedHeader : expectedRequest.headers()) {
                if (isTransportHeader(expectedHeader.name())) continue;
                String expectedValue = replacePlaceholders(expectedHeader.value(), variables);
                if (actualRequest.headers().stream().noneMatch(actualHeader ->
                        actualHeader.name().equalsIgnoreCase(expectedHeader.name())
                                && actualHeader.value().equals(expectedValue))) return false;
            }
            return true;
        } catch (Exception error) {
            api.logging().logToError("[DynamicVariables][AutoExtraction] result=LEGACY_MATCH_ERROR error="
                    + safeError(error));
            return false;
        }
    }

    private boolean isReplacementEnabled(HttpRequestToBeSent request) {
        if (!variableManager.isReplacementMasterEnabled()) return false;
        if (request.toolSource().isFromTool(ToolType.REPEATER)) return variableManager.isReplacementEnabled();
        if (request.toolSource().isFromTool(ToolType.INTRUDER)) {
            return variableManager.isReplacementIntruderEnabled();
        }
        if (request.toolSource().isFromTool(ToolType.SCANNER)) {
            return variableManager.isReplacementScannerEnabled();
        }
        if (request.toolSource().isFromTool(ToolType.PROXY)) {
            return variableManager.isReplacementProxyEnabled();
        }
        return false;
    }

    private ExtractionEngine.RequestSnapshot snapshot(HttpRequest request) {
        HttpService service = request.httpService();
        return new ExtractionEngine.RequestSnapshot(
                request.method(), service == null ? "" : service.host(),
                service == null ? 0 : service.port(), service != null && service.secure(),
                request.path(), headerLines(request.headers()), request.bodyToString());
    }

    private List<String> headerLines(List<HttpHeader> headers) {
        return headers.stream().map(header -> header.name() + ": " + header.value()).toList();
    }

    private void debug(int messageId, String variable, ExtractionOutcome outcome) {
        if (!variableManager.isExtractionDebugEnabled()) return;
        api.logging().logToOutput("[DynamicVariables][Automation] message=" + messageId
                + (variable == null ? "" : " variable=\"" + variable + "\"")
                + " result=" + outcome);
    }

    private String safeError(Exception error) {
        return error.getClass().getSimpleName();
    }

    private boolean isTransportHeader(String name) {
        return "Host".equalsIgnoreCase(name)
                || "Content-Length".equalsIgnoreCase(name)
                || "Connection".equalsIgnoreCase(name)
                || "Proxy-Connection".equalsIgnoreCase(name);
    }

    private HttpRewriteResult rewriteRequest(HttpRequest request, Map<String, String> variables,
                                             VariableNames.PlaceholderStyle placeholderStyle) {
        List<VariableRequestRewriter.HeaderValue> headerValues = request.headers().stream()
                .map(header -> new VariableRequestRewriter.HeaderValue(header.name(), header.value()))
                .toList();
        VariableRequestRewriter.RewriteResult rewriteResult = VariableRequestRewriter.rewrite(
                new VariableRequestRewriter.RequestParts(request.path(), headerValues, request.bodyToString()),
                variables, placeholderStyle);
        VariableRequestRewriter.RequestParts parts = rewriteResult.request();
        HttpRequest rewritten = request;
        if (!Objects.equals(request.path(), parts.path())) rewritten = rewritten.withPath(parts.path());

        boolean headersChanged = false;
        List<HttpHeader> newHeaders = new ArrayList<>(parts.headers().size());
        for (int index = 0; index < parts.headers().size(); index++) {
            HttpHeader originalHeader = request.headers().get(index);
            VariableRequestRewriter.HeaderValue rewrittenHeader = parts.headers().get(index);
            if (!Objects.equals(originalHeader.name(), rewrittenHeader.name())
                    || !Objects.equals(originalHeader.value(), rewrittenHeader.value())) {
                newHeaders.add(HttpHeader.httpHeader(rewrittenHeader.name(), rewrittenHeader.value()));
                headersChanged = true;
            } else {
                newHeaders.add(originalHeader);
            }
        }
        if (headersChanged) {
            rewritten = rewritten.withRemovedHeaders(rewritten.headers()).withAddedHeaders(newHeaders);
        }
        if (!Objects.equals(request.bodyToString(), parts.body())) rewritten = rewritten.withBody(parts.body());
        return new HttpRewriteResult(rewritten, rewriteResult.variablesUsed());
    }

    private String replacePlaceholders(String text, Map<String, String> variables) {
        return VariableNames.replacePlaceholders(text, variables, variableManager.getPlaceholderStyle());
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private record RequestTrace(HttpRequest originalTemplate, Set<String> variablesUsed,
                                VariableNames.PlaceholderStyle placeholderStyle, AutomationTool tool,
                                Map<String, Long> extractionSequences) {}

    private record HttpRewriteResult(HttpRequest request, List<String> variablesUsed) {}
}
