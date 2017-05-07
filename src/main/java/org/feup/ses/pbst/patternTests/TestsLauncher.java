package org.feup.ses.pbst.patternTests;

import java.util.List;
import java.util.Observable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.spoofing.AccountLockout;
import org.feup.ses.pbst.patternTests.spoofing.AuthenticationEnforcer;
import org.feup.ses.pbst.patternTests.spoofing.CredentialTokenizer;

public class TestsLauncher extends Observable {

    private ConcurrentLinkedQueue<UrlInfo> urlsToTest;
    private ConcurrentLinkedQueue<UrlInfo> urlsToTestLockout;

    private CopyOnWriteArrayList<UrlInfo> publicUrlsTested;
    private CopyOnWriteArrayList<UrlInfo> privateUrlsTested;

    private ConcurrentMap<String, WebPage> webPages;

    private ExecutorService testExecutor;
    private ExecutorService testLockoutExecutor;
    private AtomicBoolean running;
    private AtomicInteger runningTestThreads;
    private AtomicInteger maxThread;

    private TestConfAndResult pbstTest;

    public TestsLauncher(TestConfAndResult pbstTest, int timeout, ConcurrentLinkedQueue<UrlInfo> urlsToTest, ConcurrentMap<String, WebPage> webPages) {

        this.pbstTest = pbstTest;

        this.webPages = new ConcurrentHashMap<String, WebPage>();

        this.urlsToTest = new ConcurrentLinkedQueue<>();
        this.urlsToTestLockout = new ConcurrentLinkedQueue<>();

        this.publicUrlsTested = new CopyOnWriteArrayList<>();
        this.privateUrlsTested = new CopyOnWriteArrayList<>();

        if (urlsToTest == null) {
            this.urlsToTest.addAll(pbstTest.getUrlsToTest());
        } else {
            this.urlsToTest = urlsToTest;
        }

        if (webPages == null) {
            this.webPages.putAll(pbstTest.getWebPages());
        } else {
            this.webPages = webPages;
        }

        maxThread = new AtomicInteger(Runtime.getRuntime().availableProcessors());
        testExecutor = Executors.newFixedThreadPool(Math.max(1, maxThread.get() / 2));
        testLockoutExecutor = Executors.newFixedThreadPool(1);
        runningTestThreads = new AtomicInteger(0);
        running = new AtomicBoolean(false);

        //load tested urls from a saved file
        if (pbstTest != null) {
            if (pbstTest.getPublicUrlsTested() != null && !pbstTest.getPublicUrlsTested().isEmpty()) {
                for (UrlInfo info : pbstTest.getPublicUrlsTested()) {
                    publicUrlsTested.addIfAbsent(info);
                }
            }
            if (pbstTest.getPrivateUrlsTested() != null && !pbstTest.getPrivateUrlsTested().isEmpty()) {
                for (UrlInfo info : pbstTest.getPrivateUrlsTested()) {
                    privateUrlsTested.addIfAbsent(info);
                }
            }
        }
    }

    public boolean start() {

        if (urlsToTest.size() > 0) {
            running.set(true);

            Thread t = new Thread(new Runnable() {

                @Override
                public void run() {
                    //Sleep while GUI cleans interface
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e1) {
                    }
                    if (urlsToTest.size() > 0) {
                        launchTestThreads(runningTestThreads.get());
                    } else {
                        running.set(false);
                    }
                }
            });

            t.start();

            return true;
        }

        return false;
    }

    private void launchTestThreads(int startIndex) {
        for (int i = startIndex; i < maxThread.get(); i++) {
            try {
                testExecutor.submit(new Runnable() {

                    @Override
                    public void run() {
                        running.set(true);
                        runningTestThreads.incrementAndGet();

                        UrlInfo urlInfo = urlsToTest.poll();
                        urlsToTestLockout.add(urlInfo);

                        WebPage wp = webPages.get(urlInfo.getUrl());
                        FormValuesHolder holder = new FormValuesHolder(wp.getProtocol(), wp.getPort(), wp.getHost(), wp.getPath(), wp.getForms());

                        if (wp != null) {
                            //TODO - lançar os testes
                            boolean tested = false;
                            if (pbstTest.getPatterns().get(PatternEnum.SPOOFING_AE.getLiteral()) != null && pbstTest.getPatterns().get(PatternEnum.SPOOFING_AE.getLiteral()).booleanValue()) {
                                AuthenticationEnforcer authenticationEnforcer = new AuthenticationEnforcer();
                                authenticationEnforcer.startTests(wp, pbstTest, holder);
                                tested = true;
                            }

                            if (pbstTest.getPatterns().get(PatternEnum.SPOOFING_CT.getLiteral()) != null && pbstTest.getPatterns().get(PatternEnum.SPOOFING_CT.getLiteral()).booleanValue()) {
                                CredentialTokenizer credentialTokenizer = new CredentialTokenizer();
                                credentialTokenizer.startTests(wp, pbstTest, holder);
                                tested = true;
                            }

                            if (tested) {
                                if (urlInfo.getPublicAccess() != null && urlInfo.getPublicAccess().booleanValue()) {
                                    publicUrlsTested.addIfAbsent(urlInfo);
                                } else {
                                    privateUrlsTested.addIfAbsent(urlInfo);
                                }

                                setChanged();
                                notifyObservers();
                            }
                        }

                        runningTestThreads.decrementAndGet();
                    }
                });
            } catch (RejectedExecutionException e) {
                runningTestThreads.decrementAndGet();
            } catch (NullPointerException ex) {
                runningTestThreads.decrementAndGet();
            }

            if (runningTestThreads.get() == 0) {
                running.set(false);
            }
        }
    }

    public boolean startLockoutTest() {

        if (urlsToTestLockout != null && !urlsToTestLockout.isEmpty() && urlsToTest.isEmpty()) {
            running.set(true);

            Thread t = new Thread(new Runnable() {

                @Override
                public void run() {

                    if (urlsToTestLockout.size() > 0) {
                        try {
                            testLockoutExecutor.submit(new Runnable() {

                                @Override
                                public void run() {

                                    UrlInfo urlInfo = urlsToTestLockout.poll();

                                    WebPage wp = webPages.get(urlInfo.getUrl());
                                    FormValuesHolder holder = new FormValuesHolder(wp.getProtocol(), wp.getPort(), wp.getHost(), wp.getPath(), wp.getForms());

                                    if (wp != null) {
                                        boolean tested = false;
                                        if (pbstTest.getPatterns().get(PatternEnum.SPOOFING_AL.getLiteral()) != null && pbstTest.getPatterns().get(PatternEnum.SPOOFING_AL.getLiteral()).booleanValue()) {
                                            AccountLockout accountLockout = new AccountLockout();
                                            accountLockout.startTests(wp, holder, pbstTest);
                                            tested = true;
                                        }
                                        if (tested) {
                                            if (urlInfo.getPublicAccess() != null && urlInfo.getPublicAccess().booleanValue()) {
                                                publicUrlsTested.addIfAbsent(urlInfo);
                                            } else {
                                                privateUrlsTested.addIfAbsent(urlInfo);
                                            }
                                        }
                                    }

                                    setChanged();
                                    notifyObservers();
                                }
                            });
                        } catch (RejectedExecutionException e) {

                        } catch (NullPointerException ex) {
                            ex.printStackTrace();
                        }
                    }

                    running.set(false);
                }
            });

            t.start();

            return true;
        }

        return false;
    }

    public void updatePBST() {
        if (pbstTest != null) {
            pbstTest.setPublicUrlsTested(publicUrlsTested);
            pbstTest.setPrivateUrlsTested(privateUrlsTested);
            pbstTest.setTotalPublicTested(publicUrlsTested != null ? publicUrlsTested.size() : 0);
            pbstTest.setTotalPrivateTested(privateUrlsTested != null ? privateUrlsTested.size() : 0);
        }
    }

    public void stop() {
        this.running.set(false);
        try {

            getTestExecutor().shutdown();
            getTestExecutor().awaitTermination(60, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
        } finally {
            getTestExecutor().shutdownNow();
        }
    }

    public ConcurrentMap<String, WebPage> getWebPages() {
        return webPages;
    }

    public boolean isRunning() {
        return running.get();
    }

    public void setRunning(boolean running) {
        this.running.set(running);
    }

    public ExecutorService getTestExecutor() {
        return testExecutor;
    }

    public List<UrlInfo> getPublicUrlsTested() {
        return publicUrlsTested;
    }

    public List<UrlInfo> getPrivateUrlsTested() {
        return privateUrlsTested;
    }

    public AtomicInteger getRunningTestThreads() {
        return runningTestThreads;
    }

}
