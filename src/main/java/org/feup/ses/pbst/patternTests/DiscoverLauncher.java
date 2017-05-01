package org.feup.ses.pbst.patternTests;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
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
import javafx.application.Platform;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.Utils.ConcurrentUrlTreeMap;
import org.feup.ses.pbst.Utils.Utils;
import org.feup.ses.pbst.patternTests.WebPage.HeaderKey;

public class DiscoverLauncher extends Observable {

    private AtomicInteger discoveredURLs;
    private AtomicInteger publicURLs;
    private AtomicInteger privateURLs;
    private AtomicInteger notAccessibleURLs;
    private AtomicInteger urlsAccessed;

//	private ConcurrentMap<String, String> totalUrlsDiscovered;
    private ConcurrentUrlTreeMap totalUrlsDiscovered;
    private ConcurrentLinkedQueue<UrlInfo> urlsToProcess;
    private ConcurrentLinkedQueue<UrlInfo> urlsToTest;
    private CopyOnWriteArrayList<String> publicUrlsToTest;
    private CopyOnWriteArrayList<String> privateUrlsToTest;

    private ConcurrentMap<String, WebPage> webPages;

    private ExecutorService discoverExecutor;
    private AtomicBoolean running;
    private AtomicInteger runningDiscoverThreads;
    private AtomicInteger maxThread;
    private AtomicInteger minThread;

    private Integer discoverTimeWait;

    private Integer timeout;
    private int discoverStopValue;

    private TestConfAndResult pbstTest;
    private String urlLogin;
    private String urlHome;

    public DiscoverLauncher(TestConfAndResult pbstTest, int discoverStopValue) {

        this.pbstTest = pbstTest;
        this.discoverStopValue = discoverStopValue;

        this.urlLogin = pbstTest.getLoginPage();
        this.urlHome = pbstTest.getHomePage();

        this.discoveredURLs = new AtomicInteger(0);
        this.publicURLs = new AtomicInteger(0);
        this.privateURLs = new AtomicInteger(0);
        this.notAccessibleURLs = new AtomicInteger(0);
        this.urlsAccessed = new AtomicInteger(0);

        this.webPages = new ConcurrentHashMap<String, WebPage>();

//		this.totalUrlsDiscovered = new CopyOnWriteArrayList<String>();
        this.totalUrlsDiscovered = new ConcurrentUrlTreeMap();//new ConcurrentHashMap<String, String>();
        this.urlsToProcess = new ConcurrentLinkedQueue<UrlInfo>();
        this.urlsToTest = new ConcurrentLinkedQueue<UrlInfo>();
        this.publicUrlsToTest = new CopyOnWriteArrayList<String>();
        this.privateUrlsToTest = new CopyOnWriteArrayList<String>();
    }

    public void load() {
        if (pbstTest != null) {
            discoveredURLs.set(pbstTest.getTotalDiscovered());
            publicURLs.set(pbstTest.getTotalPublic());
            privateURLs.set(pbstTest.getTotalPrivate());
            notAccessibleURLs.set(pbstTest.getTotalNotAccessible());
            urlsAccessed.set(pbstTest.getTotalAccessed());

            if (pbstTest.getTotalUrlsDiscovered() != null) {
                totalUrlsDiscovered.set(pbstTest.getTotalUrlsDiscovered());
            }

            if (pbstTest.getUrlsToProcess() != null) {
                while (!pbstTest.getUrlsToProcess().isEmpty()) {
                    urlsToProcess.add(pbstTest.getUrlsToProcess().poll());
                }
            }

            if (pbstTest.getUrlsToTest() != null) {
                while (!pbstTest.getUrlsToTest().isEmpty()) {
                    urlsToTest.add(pbstTest.getUrlsToTest().poll());
                }
            }

            if (pbstTest.getPublicUrlsToTest() != null) {
                for (String s : pbstTest.getPublicUrlsToTest()) {
                    publicUrlsToTest.addIfAbsent(s);
                }
            }

            if (pbstTest.getPrivateUrlsToTest() != null) {
                for (String s : pbstTest.getPrivateUrlsToTest()) {
                    privateUrlsToTest.addIfAbsent(s);
                }
            }

            if (pbstTest.getWebPages() != null && !pbstTest.getWebPages().isEmpty()) {
                for (String key : pbstTest.getWebPages().keySet()) {
                    webPages.put(key, pbstTest.getWebPages().get(key));
                }
            }
        }

        if (urlLogin != null && !"".equals(urlLogin)) {
            UrlInfo ui = new UrlInfo(urlLogin);
            if (totalUrlsDiscovered.addUrl(ui.getUrl())) {
                discoveredURLs.incrementAndGet();
                urlsToProcess.add(ui);
            }
        }

        if (urlHome != null && !"".equals(urlHome) && !urlHome.equals(urlLogin)) {
            UrlInfo ui = new UrlInfo(urlHome);
            if (totalUrlsDiscovered.addUrl(ui.getUrl())) {
                discoveredURLs.incrementAndGet();
                urlsToProcess.add(ui);
            }
        }
    }

    public boolean start(int timeout) {
        this.timeout = timeout;

        this.discoverTimeWait = 5000;

        if (urlsToProcess != null && urlsToProcess.size() > 0) {
            maxThread = new AtomicInteger(Runtime.getRuntime().availableProcessors());
            minThread = new AtomicInteger(Math.max(1, maxThread.get() / 2));
            running = new AtomicBoolean(true);
            discoverExecutor = Executors.newFixedThreadPool(maxThread.get());
            runningDiscoverThreads = new AtomicInteger(0);

            Thread t = new Thread(new Runnable() {

                @Override
                public void run() {
                    //Sleep while GUI cleans interface
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e1) {
                    }
                    int countFailLaunch = 0;
                    while (running.get()) {
                        countFailLaunch++;

                        if (urlsToProcess.size() > 0) {
                            countFailLaunch = 0;
                            launchDiscoveryThreads(runningDiscoverThreads.get());
                        }

                        try {
                            Thread.sleep(200);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        }

                        if (countFailLaunch > 50) {
                            break;
                        }
                    }

                    stop();
                }
            });

            t.start();

            return true;
        }

        return false;
    }

    public void launchDiscoveryThreads(int startIndex) {

        for (int i = startIndex; i < Math.min(urlsToProcess.size(), maxThread.get()); i++) {

            try {
                discoverExecutor.submit(new Runnable() {

                    @Override
                    public void run() {

                        Integer count = 0;

                        runningDiscoverThreads.incrementAndGet();

                        while (running.get() && !urlsToProcess.isEmpty()) {

                            UrlInfo url = urlsToProcess.poll();

                            if (url == null || url.getUrl() == null) {
                                continue;
                            }

                            try {
                                new URL(url.getUrl());
                            } catch (MalformedURLException e) {
                                continue;
                            }

                            WebPage webPage = new WebPage(url.getUrl(), urlHome, urlLogin);
                            UrlInfo urlInfo = new UrlInfo(url.getUrl());

                            boolean addToTest = false;
                            boolean skip = false;

                            if (webPage.openConnection(timeout)) {
                                urlsAccessed.incrementAndGet();

                                outer:
                                for (HeaderKey hk : webPage.getHeaders().keySet()) {
                                    if (hk.getHeader() != null && hk.getHeader().equals("Content-Type")) {
                                        for (String content : webPage.getHeaders().get(hk)) {
                                            if (content != null && content.toLowerCase().contains("image")) {
                                                skip = true;
                                                break outer;
                                            }
                                        }
                                    }
                                }

                                int statusCode = webPage.getStatusCode();

                                if (statusCode == 0 || statusCode == 500) {

                                    if (maxThread.decrementAndGet() < minThread.get()) {
                                        maxThread.set(minThread.get());
                                        System.out.println("Número de threads máximas = " + maxThread.get());
                                    }

                                    try {
                                        Thread.sleep(discoverTimeWait * maxThread.get());
                                    } catch (InterruptedException e) {
                                    }

                                    if (url.isFirstTry()) {
                                        url.setFirstTry(false);
                                        urlsToProcess.add(url);
                                    } else {
                                        notAccessibleURLs.incrementAndGet();
                                    }
                                } else if (statusCode == 400 || statusCode == 404) {
                                    notAccessibleURLs.incrementAndGet();
                                } else if (statusCode == 200
                                        || statusCode == 301 || statusCode == 302 || statusCode == 303 || statusCode == 307
                                        || statusCode == 401 || statusCode == 402 || statusCode == 403) {

                                    processResponse(webPage, urlInfo);

                                    addToTest = true;
                                } else {
                                    System.err.println("" + webPage.getStatusCode() + " ->" + url.getUrl());
                                }
                            } else {
                                privateURLs.incrementAndGet();

                                urlInfo.setPublicAccess(false);

                                addToTest = true;
                            }

                            //TODO - remove webPage.getForms() != null && !webPage.getForms().isEmpty()
                            //if new tests became available and they d'ont need forms to perform the test
                            if (addToTest && !skip && webPage.getForms() != null && !webPage.getForms().isEmpty()) {
                                if (urlInfo.getPublicAccess() != null && urlInfo.getPublicAccess().booleanValue()) {
                                    if (publicUrlsToTest.addIfAbsent(urlInfo.getUrlWithoutParameters())) {
                                        if (webPages.get(urlInfo.getUrl()) == null) {
                                            webPages.put(urlInfo.getUrl(), webPage);
                                            urlsToTest.add(urlInfo);
                                        }
                                    }
                                } else {
                                    if (privateUrlsToTest.addIfAbsent(urlInfo.getUrlWithoutParameters())) {
                                        if (webPages.get(urlInfo.getUrl()) == null) {
                                            webPages.put(urlInfo.getUrl(), webPage);
                                            urlsToTest.add(urlInfo);
                                        }
                                    }
                                }
                            }

                            setChanged();
                            notifyObservers();

                            count++;
                            //Sleep to free resources or to avoid denial of service
                            try {
                                if (count > 10) {
                                    count = 0;
                                    Thread.sleep(discoverTimeWait);
                                }
                            } catch (InterruptedException e) {
                            }
                        }

                        runningDiscoverThreads.decrementAndGet();

                        if (urlsToProcess.size() > 0 && runningDiscoverThreads.get() <= 0) {
                            try {
                                Platform.runLater(new Runnable() {
                                    public void run() {
                                        launchDiscoveryThreads(runningDiscoverThreads.get());
                                    }
                                });
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    }
                });
            } catch (RejectedExecutionException e) {
            } catch (NullPointerException ex) {
                ex.printStackTrace();
            }

            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
            }
        }
    }

    private void processResponse(final WebPage webPage, final UrlInfo urlInfo) {
        if (webPage.loadPage()) {
            webPage.processPage(pbstTest);

            if (webPage.isNeedsAuthentication()) {
                privateURLs.incrementAndGet();

                urlInfo.setPublicAccess(false);
            } else {
                publicURLs.incrementAndGet();

                urlInfo.setPublicAccess(true);
            }
        } else {
            privateURLs.incrementAndGet();

            urlInfo.setPublicAccess(false);
        }

        if (discoveredURLs.get() < discoverStopValue) {
            List<String> links = new ArrayList<String>(webPage.getLinks());
            for (String s : links) {
                if (s != null && !"".equals(s)) {

                    UrlInfo urlTemp = new UrlInfo(Utils.getCompleteLink(s, webPage.getProtocol(), webPage.getPort(), webPage.getHost(), webPage.getPath()));

                    if (totalUrlsDiscovered.addUrl(urlTemp.getUrl())) {
                        urlsToProcess.add(urlTemp);

                        discoveredURLs.incrementAndGet();
                    }
                }
            }
        }
    }

    public void updatePBST() {
        if (pbstTest != null) {
            pbstTest.setTotalDiscovered(discoveredURLs.get());
            pbstTest.setTotalPublic(publicURLs.get());
            pbstTest.setTotalPrivate(privateURLs.get());
            pbstTest.setTotalNotAccessible(notAccessibleURLs.get());
            pbstTest.setTotalAccessed(urlsAccessed.get());

//			pbstTest.setTotalUrlsDiscovered(totalUrlsDiscovered.keySet());
            pbstTest.setTotalUrlsDiscovered(totalUrlsDiscovered);
            pbstTest.setTotalSelectedToBeTested(webPages.size());
            pbstTest.setUrlsToProcess(urlsToProcess);
            pbstTest.setUrlsToTest(urlsToTest);
            pbstTest.setPublicUrlsToTest(publicUrlsToTest);
            pbstTest.setPrivateUrlsToTest(privateUrlsToTest);

            pbstTest.setWebPages(webPages);
        }
    }

    public void stop() {
        this.running.set(false);
        try {
            getDiscoverExecutor().shutdown();
            getDiscoverExecutor().awaitTermination(10, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            e.printStackTrace();
        } finally {
            getDiscoverExecutor().shutdownNow();
        }
    }

    public ConcurrentMap<String, WebPage> getWebPages() {
        return webPages;
    }

    public boolean isRunning() {
        return running != null && running.get();
    }

    public void setRunning(boolean running) {
        this.running.set(running);
    }

    public int getNotAccessibleURLs() {
        return notAccessibleURLs.get();
    }

    public int getDiscoveredURLs() {
        return discoveredURLs.get();
    }

    public ExecutorService getDiscoverExecutor() {
        return discoverExecutor;
    }

    public Integer getCountRunningThreads() {
        return runningDiscoverThreads.get();
    }

    public int getPublicURLs() {
        return publicURLs.get();
    }

    public int getPrivateURLs() {
        return privateURLs.get();
    }

    public AtomicInteger getUrlsAccessed() {
        return urlsAccessed;
    }

    public CopyOnWriteArrayList<String> getPublicUrlsToTest() {
        return publicUrlsToTest;
    }

    public CopyOnWriteArrayList<String> getPrivateUrlsToTest() {
        return privateUrlsToTest;
    }

    public ConcurrentLinkedQueue<UrlInfo> getUrlsToTest() {
        return urlsToTest;
    }

    public ConcurrentLinkedQueue<UrlInfo> getUrlsToProcess() {
        return urlsToProcess;
    }

}
