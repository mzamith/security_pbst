package org.feup.ses.pbst.tests;

import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;

public class CredentialsTransport extends Test {

    private static long id = 0;

    private long myId = 0;

    public CredentialsTransport() {
        super();
    }

    public void test(WebPage webPage, FormValuesHolder holder, PatternEnum pattern) {
        super.setWebPage(webPage);

        myId = ++id;

        boolean vulnerable = false;

        if (holder.getInputUsername() != null && holder.getInputPassword() != null
                && (("POST".equals(holder.getMethod().toUpperCase()) && holder.getAction() != null && !holder.getAction().contains("https"))
                || "GET".equals(holder.getMethod().toUpperCase()))) {
            vulnerable = true;
        }

        if (vulnerable) {
            webPage.addTestResult(pattern, TestResultEnum.VULNERABLE, "Credentials Transport", "Authentication credentials are not transported over an encrypted channel.");
        } else {
            webPage.addTestResult(pattern, TestResultEnum.SECURE);
        }
    }

    public long getMyId() {
        return myId;
    }
}
