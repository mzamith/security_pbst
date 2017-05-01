package org.feup.ses.pbst.tests;

import java.util.Observable;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.WebPage;

public abstract class Test extends Observable {

    private WebPage webPage;
    private TestConfAndResult pbstTest;

    public WebPage getWebPage() {
        return webPage;
    }

    public void setWebPage(WebPage webPage) {
        this.webPage = webPage;
    }

    public TestConfAndResult getPbstTest() {
        return pbstTest;
    }

    public void setPbstTest(TestConfAndResult pbstTest) {
        this.pbstTest = pbstTest;
    }
}
