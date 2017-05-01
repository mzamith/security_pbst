package org.feup.ses.pbst.GUI;

import java.util.Observable;
import java.util.Observer;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.DiscoverLauncher;
import org.feup.ses.pbst.patternTests.TestsLauncher;

public class TaskProcessor extends Observable implements Observer {

    private TestConfAndResult pbstTest;
    private int timeout;
    private int discoverStopValue;

    private DiscoverLauncher discoverLauncher;
    private TestsLauncher testLauncher;

    private Long currentTimeUpdate;
    private Long lastTimeUpdate;

    private Long lastTimeTestSetToBeTested;
    private boolean discoverStage = false;
    private boolean testStage = false;

    private boolean finished = false;

    public TaskProcessor(int timeout, int discoverStopValue, TestConfAndResult pbstTest) {
        this.timeout = timeout * 1000;
        this.discoverStopValue = discoverStopValue;
        this.pbstTest = pbstTest;

        discoverLauncher = new DiscoverLauncher(pbstTest, this.discoverStopValue);
        discoverLauncher.addObserver(this);
        discoverLauncher.load();
    }

    public boolean start() {
        currentTimeUpdate = System.currentTimeMillis();
        lastTimeUpdate = System.currentTimeMillis();

        //this not starts if exists a previous discovered stage saved
        if (!discoverLauncher.start(timeout)) {
            testStage = true;

            testLauncher = new TestsLauncher(pbstTest, this.timeout, null, null);
            testLauncher.addObserver(this);

            if (!testLauncher.start()) {
                return false;
            } else {
                notifyAllObservers();
            }
        } else {
            testLauncher = new TestsLauncher(pbstTest, this.timeout, discoverLauncher.getUrlsToTest(), discoverLauncher.getWebPages());
            testLauncher.addObserver(this);

            discoverStage = true;
        }

        return true;
    }

    public void stop() {
        if (discoverLauncher != null && discoverLauncher.isRunning()) {
            discoverLauncher.stop();
            discoverLauncher.updatePBST();
        }
        if (testLauncher != null && testLauncher.isRunning()) {
            testLauncher.stop();
            testLauncher.updatePBST();
        }

        notifyAllObservers();

        setChanged();
        notifyObservers(GUI.STOP_TEST_STAGE);

        setChanged();
        notifyObservers(GUI.UPDATE);
    }

    public boolean isDiscoverStage() {
        return discoverStage;
    }

    public boolean isTestStage() {
        return testStage;
    }

    public DiscoverLauncher getDiscoverLauncher() {
        return discoverLauncher;
    }

    public TestsLauncher getTestLauncher() {
        return testLauncher;
    }

    public boolean isFinished() {
        return finished;
    }

    @Override
    public void update(Observable arg0, Object arg) {
        currentTimeUpdate = System.currentTimeMillis();

        if ((currentTimeUpdate - lastTimeUpdate) > 250) {//Updates GUI with 1/4 second interval
            lastTimeUpdate = currentTimeUpdate;

            notifyAllObservers();

        }
        if (!finished) {
            boolean startedLockout = false;

            if (isDiscoverStage()) {

                int totalDiscoveredAnVerified = discoverLauncher.getPublicURLs() + discoverLauncher.getPrivateURLs() + discoverLauncher.getNotAccessibleURLs();

                if ((totalDiscoveredAnVerified >= discoverStopValue && discoverLauncher.getDiscoveredURLs() == totalDiscoveredAnVerified) || discoverLauncher.getUrlsToProcess().isEmpty()) {
                    discoverStage = false;
                }

                if (discoverStage && discoverLauncher.getDiscoveredURLs() > (discoverLauncher.getNotAccessibleURLs() + discoverLauncher.getPrivateURLs() + discoverLauncher.getPublicURLs())) {
                    discoverLauncher.launchDiscoveryThreads(discoverLauncher.getCountRunningThreads());
                }

                if (!discoverStage) {
                    testStage = true;
                }

                if (testStage) {
                    setChanged();
                    notifyObservers(GUI.STOP_DISCOVER_STAGE);
                }
            }

            if (isTestStage()) {
                if (pbstTest.hasPatternsCheckedToTest()) {
                    if (!testLauncher.start()) {
                        testStage = false;
                    }
                } else {
                    testStage = false;
                }
            }

            if (!isDiscoverStage() && !isTestStage() && pbstTest.isToTestLockout()) {
                if (testLauncher.getWebPages() != null && !testLauncher.getWebPages().isEmpty()) {
                    startedLockout = testLauncher.startLockoutTest();
                }
            }

            if (!isDiscoverStage() && !isTestStage() && !startedLockout) {

                finished = true;

                stop();
            }

        }
    }

    private void notifyAllObservers() {
        setChanged();
        notifyObservers(GuiTopBar.TAG);

        setChanged();
        notifyObservers(GuiTestsRun.TAG);
    }
}
