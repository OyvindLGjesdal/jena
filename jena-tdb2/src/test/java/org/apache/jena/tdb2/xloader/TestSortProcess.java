/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 *   SPDX-License-Identifier: Apache-2.0
 */

package org.apache.jena.tdb2.xloader;

import static org.junit.jupiter.api.Assertions.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.jena.atlas.RuntimeIOException;
import org.apache.jena.graph.NodeFactory;
import org.apache.jena.sparql.core.Quad;
import org.apache.jena.tdb2.DatabaseMgr;
import org.apache.jena.tdb2.TDBException;
import org.apache.jena.tdb2.sys.TDBInternal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

public class TestSortProcess {
    @TempDir Path directory;

    private List<String> command(String mode) {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        return List.of(java, "-cp", System.getProperty("java.class.path"), Child.class.getName(), mode);
    }

    @Test
    public void concurrentPipes() {
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            byte[] bytes = "0123456789abcdef\n".repeat(100_000).getBytes(StandardCharsets.UTF_8);
            try ( SortProcess sort = new SortProcess(command("echo")) ) {
                byte[] result = sort.run(output -> output.write(bytes), (input, check) -> {
                    byte[] received = input.readAllBytes();
                    check.run();
                    return received;
                });
                assertArrayEquals(bytes, result);
            }
        });
    }

    @Test
    public void producerFailure() {
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            var failure = new IllegalArgumentException("parser failed");
            AtomicBoolean committed = new AtomicBoolean();
            RuntimeException actual = assertThrows(RuntimeException.class, () -> {
                try ( SortProcess sort = new SortProcess(command("echo")) ) {
                    sort.run(output -> { throw failure; }, (input, check) -> {
                        input.readAllBytes();
                        check.run();
                        committed.set(true);
                        return null;
                    });
                }
            });
            assertSame(failure, actual);
            assertFalse(committed.get());
        });
    }

    @Test
    public void producerFailureAllowsTransactionRollback() {
        assertTimeoutPreemptively(Duration.ofSeconds(30), () -> {
            String location = directory.resolve("db").toString();
            Quad quad = Quad.create(Quad.defaultGraphIRI, NodeFactory.createURI("urn:s"),
                    NodeFactory.createURI("urn:p"), NodeFactory.createURI("urn:o"));
            var failure = new IllegalArgumentException("parser failed during transaction");
            CountDownLatch transactionStarted = new CountDownLatch(1);
            AtomicBoolean consumerInterrupted = new AtomicBoolean();
            AtomicBoolean consumerStopped = new AtomicBoolean();
            AtomicReference<RuntimeException> consumerFailure = new AtomicReference<>();
            var dsg = DatabaseMgr.connectDatasetGraph(location);
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(dsg) ) {
                RuntimeException actual = assertThrows(RuntimeException.class, () -> {
                    try ( SortProcess sort = new SortProcess(command("echo")) ) {
                        sort.run(output -> {
                            try { assertTrue(transactionStarted.await(5, TimeUnit.SECONDS)); }
                            catch (InterruptedException ex) {
                                Thread.currentThread().interrupt();
                                throw new TDBException("Producer interrupted", ex);
                            }
                            throw failure;
                        }, (input, check) -> {
                            try {
                                dsg.executeWrite(() -> {
                                    dsg.add(quad);
                                    // Fail the producer only after there is data to roll back.
                                    transactionStarted.countDown();
                                    try { input.readAllBytes(); }
                                    catch (IOException ex) { throw new RuntimeIOException(ex); }
                                    check.run();
                                });
                                return null;
                            } catch (RuntimeException ex) {
                                consumerFailure.set(ex);
                                throw ex;
                            } finally {
                                consumerInterrupted.set(Thread.currentThread().isInterrupted());
                                consumerStopped.set(true);
                            }
                        });
                    }
                });
                assertSame(failure, actual);
                assertTrue(consumerStopped.get());
                assertFalse(consumerInterrupted.get(), "Rollback must not be interrupted");
                assertNotNull(consumerFailure.get());
                assertEquals(0, consumerFailure.get().getSuppressed().length,
                        "Rollback must not add a suppressed failure");
                assertFalse(dsg.calculateRead(() -> dsg.contains(quad)));
                // Also check the original coordinator's writer lock before expelling it.
                dsg.executeWrite(() -> dsg.add(quad));
            }
            var reopened = DatabaseMgr.connectDatasetGraph(location);
            try ( BulkLoaderX.Cleanup cleanup = () -> TDBInternal.expel(reopened) ) {
                assertTrue(reopened.calculateRead(() -> reopened.contains(quad)));
                reopened.executeWrite(() -> reopened.delete(quad));
            }
        });
    }

    @Test
    public void consumerFailureWhileProducerIsWriting() {
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            var failure = new IllegalStateException("index writer failed");
            AtomicBoolean producerStopped = new AtomicBoolean();
            CountDownLatch writing = new CountDownLatch(1);
            RuntimeException actual = assertThrows(RuntimeException.class, () -> {
                try ( SortProcess sort = new SortProcess(command("echo")) ) {
                    sort.run(output -> {
                        try {
                            writing.countDown();
                            byte[] bytes = new byte[65536];
                            while (!Thread.currentThread().isInterrupted())
                                output.write(bytes);
                        } finally {
                            producerStopped.set(true);
                        }
                    }, (input, check) -> {
                        try { assertTrue(writing.await(5, TimeUnit.SECONDS)); }
                        catch (InterruptedException ex) { throw new RuntimeException(ex); }
                        throw failure;
                    });
                }
            });
            assertSame(failure, actual);
            assertTrue(producerStopped.get());
        });
    }

    @Test
    public void largeStderrAndNonzeroExit() {
        assertTimeoutPreemptively(Duration.ofSeconds(15), () -> {
            AtomicBoolean committed = new AtomicBoolean();
            TDBException ex = assertThrows(TDBException.class, () -> {
                try ( SortProcess sort = new SortProcess(command("fail")) ) {
                    sort.run(output -> {}, (input, check) -> {
                        input.readAllBytes();
                        check.run();
                        committed.set(true);
                        return null;
                    });
                }
            });
            assertTrue(ex.getMessage().contains("Sort RC = 7"));
            assertTrue(ex.getMessage().contains("sort diagnostic"));
            assertTrue(ex.getMessage().contains("stderr truncated"));
            assertTrue(ex.getMessage().length() < 66_000);
            assertFalse(committed.get());
        });
    }

    @Test
    public void interruptionStopsChildAndRestoresInterrupt() throws Exception {
        CountDownLatch started = new CountDownLatch(1);
        AtomicLong pid = new AtomicLong();
        AtomicBoolean interrupted = new AtomicBoolean();
        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread caller = new Thread(() -> {
            try ( SortProcess sort = new SortProcess(command("wait")) ) {
                sort.run(output -> {}, (input, check) -> {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
                    pid.set(Long.parseLong(reader.readLine()));
                    started.countDown();
                    reader.readLine();
                    check.run();
                    return null;
                });
            } catch (Throwable ex) {
                failure.set(ex);
                interrupted.set(Thread.currentThread().isInterrupted());
            }
        });
        caller.start();
        try {
            assertTrue(started.await(10, TimeUnit.SECONDS));
        } finally {
            caller.interrupt();
            caller.join(10_000);
        }
        assertFalse(caller.isAlive());
        assertInstanceOf(TDBException.class, failure.get());
        assertTrue(interrupted.get());
        assertFalse(ProcessHandle.of(pid.get()).map(ProcessHandle::isAlive).orElse(false));
    }

    /** Separate JVM so these process tests do not depend on shell utilities or GNU sort. */
    public static class Child {
        public static void main(String[] args) throws Exception {
            switch (args[0]) {
                case "echo" -> System.in.transferTo(System.out);
                case "fail" -> {
                    System.err.print("sort diagnostic\n");
                    System.err.print("x".repeat(256 * 1024));
                    System.exit(7);
                }
                case "wait" -> {
                    System.out.println(ProcessHandle.current().pid());
                    System.out.flush();
                    Thread.sleep(60_000);
                }
                default -> throw new IllegalArgumentException(args[0]);
            }
        }
    }
}
