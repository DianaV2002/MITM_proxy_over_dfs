package org.example.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Supplier;
import java.util.concurrent.TimeUnit;

public class RetryUtil {
    private static final Logger logger = LoggerFactory.getLogger(RetryUtil.class);
    private static final int MAX_RETRIES = 3;
    private static final long RETRY_DELAY_MS = 1000;

    public static <T> T withRetry(Supplier<T> operation, String operationName) throws Exception {
        int attempts = 0;
        Exception lastException = null;

        while (attempts < MAX_RETRIES) {
            try {
                attempts++;
                logger.debug("Attempting {} (attempt {}/{})", operationName, attempts, MAX_RETRIES);
                return operation.get();
            } catch (Exception e) {
                lastException = e;
                if (attempts < MAX_RETRIES) {
                    logger.warn("{} failed (attempt {}/{}): {}", operationName, attempts, MAX_RETRIES, e.getMessage());
                    try {
                        Thread.sleep(RETRY_DELAY_MS);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new RuntimeException("Retry interrupted", ie);
                    }
                }
            }
        }

        logger.error("{} failed after {} attempts", operationName, MAX_RETRIES, lastException);
        throw lastException;
    }

    public static void withRetry(Runnable operation, String operationName) throws Exception {
        withRetry(() -> {
            operation.run();
            return null;
        }, operationName);
    }
} 