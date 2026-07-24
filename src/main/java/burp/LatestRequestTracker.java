package burp;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

final class LatestRequestTracker {
    private final AtomicLong sequence = new AtomicLong();
    private final Map<String, Long> latestByRule = new ConcurrentHashMap<>();

    long register(String variable) {
        long value = sequence.incrementAndGet();
        latestByRule.put(variable, value);
        return value;
    }

    boolean isLatest(String variable, long candidateSequence) {
        return Long.valueOf(candidateSequence).equals(latestByRule.get(variable));
    }
}
