# AGENTS.md - Developer & Agent Guidelines for Dynamic Variables

This document provides context, architecture rules, and build instructions for AI coding assistants working on the **Dynamic Variables** Burp Suite extension.

---

## 1. Project Overview & Architecture

- **Description**: A modern Burp Suite extension built with the **Montoya API** to automate dynamic variable extraction, request rewriting/substitution, cascading session recovery, and folder management across Burp tools (Repeater, Intruder, Proxy, Scanner).
- **Language & Build**: Java 17+, Gradle (Wrapper included).
- **Core Dependency**: `net.portswigger.burp.extensions:montoya-api:2026.7` (`compileOnly`).

### Key Components

- `src/main/java/burp/DynamicVariables.java`: Main entry point implementing `BurpExtension`. Handles extension setup, registration of tab components, HTTP handlers, context menus, and unload handler.
- `src/main/java/burp/VariableManager.java`: Central manager for variable state, extraction rules, folder hierarchy, configuration UI tabs, and project persistence.
- `src/main/java/burp/VariableHttpHandler.java`: Implements Montoya `HttpHandler`. Performs automatic placeholder substitution on outbound requests and extraction rule evaluation on inbound responses.
- `src/main/java/burp/ExtractionEngine.java`: Evaluates multi-source extraction targets (Regex, JSON Path, Header, Body, Full Response).
- `src/main/java/burp/VariableContextMenuProvider.java`: Context menu integration for selected text mapping to dynamic variables.
- `src/main/java/burp/StagedRefreshCoordinator.java`: Coordinates cascading variable updates and session recovery.

---

## 2. Build & Test Commands

Always verify changes by running unit tests:

```bash
# Run unit tests
./gradlew test

# Build distribution JAR artifact
./gradlew jar
```

---

## 3. Strict Development Guidelines

When modifying this repository, strictly adhere to the following rules:

1. **BApp Store Acceptance Criteria**:
   - Always verify compliance against `BAPP_STORE_CHECKLIST.md`.
2. **Threading & Responsiveness**:
   - **NEVER** perform HTTP requests or slow I/O operations on the Swing Event Dispatch Thread (EDT). Use background threads (`new Thread(...)`).
   - All Swing UI mutations from background threads must be wrapped in `SwingUtilities.invokeLater(...)`.
   - Exceptions inside background threads must be caught and logged using `api.logging().logToError(...)`.
3. **Burp Networking**:
   - Issue all outbound HTTP requests through Montoya's `api.http().issueHttpRequest(...)`. Do not use standard Java HTTP libraries (`java.net.URL`, `HttpClient`, etc.) to ensure upstream proxy and session rules are honored.
4. **GUI Dialog Parent Window**:
   - Every `JDialog`, `JOptionPane`, or popup must set its parent window using `api.userInterface().swingUtils().suiteFrame()` or an appropriate parent container component.
5. **Memory & Performance**:
   - Do not retain long-term references to large `HttpRequestResponse` objects or Proxy history. Use minimal representations (such as `LatestRequestTracker` or Base64 request templates).
