package org.feup.ses.pbst.patternTests.spoofing;

import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;
import org.feup.ses.pbst.tests.*;

public class CredentialTokenizer extends Spoofing {

    private CheckTokens tokenChecker = null;

    public void startTests(WebPage webPage, TestConfAndResult pbstTest, FormValuesHolder holder) {

        tokenChecker = new CheckTokens();
        tokenChecker.test(webPage, pbstTest, holder, PatternEnum.SPOOFING_CT);

    }

}
