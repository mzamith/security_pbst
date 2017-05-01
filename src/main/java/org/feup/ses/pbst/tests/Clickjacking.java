package org.feup.ses.pbst.tests;

import java.util.List;
import java.util.Map;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.patternTests.WebPage;
import org.feup.ses.pbst.patternTests.WebPage.HeaderKey;

public class Clickjacking extends Test {

    private static long id = 0;

    private long myId = 0;

    public Clickjacking() {
        super();
    }

    public void test(WebPage webPage, PatternEnum pattern) {
        super.setWebPage(webPage);

        myId = ++id;

        Map<HeaderKey, List<String>> headersMap = webPage.getHeaders();
        boolean vulnerable = true;

        for (HeaderKey key : headersMap.keySet()) {
            if ("x-frame-options".equals(key.getHeader().toLowerCase())) {
                List<String> options = headersMap.get(key);

                for (String option : options) {
                    if (option == null || "".equals(option)) {
                        continue;
                    }
                    if ("DENY".equals(option.toUpperCase())) {
                        vulnerable = false;
                        break;
                    }
                    if ("SAMEORIGIN".equals(option.toUpperCase())) {
                        vulnerable = false;
                        break;
                    }
                    if ("ALLOW-FROM".equals(option.toUpperCase())) {
                        vulnerable = false;
                        break;
                    }
                }
            }
        }

        if (vulnerable) {
            webPage.addTestResult(pattern, TestResultEnum.VULNERABLE, "Clickjacking", "Missing header x-frame-options");
        } else {
            webPage.addTestResult(pattern, TestResultEnum.SECURE);
        }
    }

    public long getMyId() {
        return myId;
    }
}
