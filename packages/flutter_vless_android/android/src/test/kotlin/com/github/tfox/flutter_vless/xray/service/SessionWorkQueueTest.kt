package com.github.tfox.flutter_vless.xray.service

import org.junit.Assert.*
import org.junit.Test
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class SessionWorkQueueTest {
    private fun await(latch: CountDownLatch) = assertTrue(latch.await(5, TimeUnit.SECONDS))

    @Test fun acceptedWorkDrainsBeforeExactlyOneCleanupAndLateCallbacksDoNotRun() {
        val executor = ScheduledThreadPoolExecutor(1)
        val queue = SessionWorkQueue(executor)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val done = CountDownLatch(1)
        val events = Collections.synchronizedList(mutableListOf<String>())
        try {
            assertTrue(queue.execute { entered.countDown(); release.await(5, TimeUnit.SECONDS); events.add("first") })
            await(entered)
            assertTrue(queue.execute { events.add("second") })
            assertTrue(queue.close { events.add("cleanup"); done.countDown() })
            assertFalse(queue.close { events.add("duplicate cleanup") })
            assertFalse(queue.execute { events.add("late network callback") })
            assertFalse(queue.schedule({ events.add("late worker callback") }, 0, TimeUnit.MILLISECONDS))
            release.countDown()
            await(done)
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals(listOf("first", "second", "cleanup"), events.toList())
        } finally {
            release.countDown()
            queue.close { }
            executor.shutdownNow()
        }
    }

    @Test fun closeCancelsPendingRetriesAndDoesNotWaitForTheirDelay() {
        val executor = ScheduledThreadPoolExecutor(1)
        val queue = SessionWorkQueue(executor)
        val ran = AtomicInteger()
        val done = CountDownLatch(1)
        try {
            assertTrue(queue.schedule({ ran.incrementAndGet() }, 1, TimeUnit.HOURS))
            assertTrue(queue.close { done.countDown() })
            await(done)
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals(0, ran.get())
            assertTrue(executor.queue.isEmpty())
        } finally {
            queue.close { }
            executor.shutdownNow()
        }
    }

    @Test fun aStartedRetryFinishesBeforeCleanupAndCannotRearmItself() {
        val executor = ScheduledThreadPoolExecutor(1)
        val queue = SessionWorkQueue(executor)
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val done = CountDownLatch(1)
        val events = Collections.synchronizedList(mutableListOf<String>())
        try {
            assertTrue(queue.schedule({
                entered.countDown()
                release.await(5, TimeUnit.SECONDS)
                events.add("retry finished")
                assertFalse(queue.schedule({ events.add("rearmed") }, 0, TimeUnit.MILLISECONDS))
            }, 0, TimeUnit.MILLISECONDS))
            await(entered)
            queue.close { events.add("cleanup"); done.countDown() }
            release.countDown()
            await(done)
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals(listOf("retry finished", "cleanup"), events.toList())
        } finally {
            release.countDown()
            queue.close { }
            executor.shutdownNow()
        }
    }

    @Test fun concurrentAdmissionAndCloseNeverAcceptsWorkAfterFinalCleanup() {
        val executor = ScheduledThreadPoolExecutor(1)
        val queue = SessionWorkQueue(executor)
        val callers = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        val cleaned = CountDownLatch(1)
        val ran = AtomicInteger()
        val accepted = AtomicInteger()
        val cleanupCount = AtomicInteger()
        val workAfterCleanup = AtomicInteger()
        try {
            val results = (0 until 7).map {
                callers.submit {
                    start.await()
                    repeat(300) {
                        if (queue.execute {
                            if (cleanupCount.get() != 0) workAfterCleanup.incrementAndGet()
                            ran.incrementAndGet()
                        }) accepted.incrementAndGet()
                    }
                }
            }
            val closer = callers.submit {
                start.await()
                queue.close { cleanupCount.incrementAndGet(); cleaned.countDown() }
            }
            start.countDown()
            results.forEach { it.get(5, TimeUnit.SECONDS) }
            closer.get(5, TimeUnit.SECONDS)
            await(cleaned)
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS))
            assertEquals(accepted.get(), ran.get())
            assertEquals(1, cleanupCount.get())
            assertEquals(0, workAfterCleanup.get())
            assertFalse(queue.execute { fail("closed callback must not run") })
        } finally {
            start.countDown()
            queue.close { }
            callers.shutdownNow()
            executor.shutdownNow()
        }
    }

    @Test fun anUnexpectedLiveExecutorRejectionIsNotHidden() {
        val executor = ScheduledThreadPoolExecutor(1)
        val queue = SessionWorkQueue(executor)
        executor.shutdown()
        try {
            queue.execute { fail("must not run") }
            fail("A live queue must not hide an unexpectedly stopped executor")
        } catch (_: RejectedExecutionException) { }
        try {
            queue.schedule({ fail("must not run") }, 1, TimeUnit.SECONDS)
            fail("A live queue must not hide a rejected retry")
        } catch (_: RejectedExecutionException) { }
    }
}
