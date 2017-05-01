package org.feup.ses.pbst.patternTests.spoofing;

import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;
import org.feup.ses.pbst.tests.LockOutMechanism;

public class AccountLockout extends Spoofing {

    private LockOutMechanism lockOutMechanism = null;

    public void startTests(WebPage webPage, FormValuesHolder holder, TestConfAndResult pbstTest) {
        lockOutMechanism = new LockOutMechanism();
        lockOutMechanism.test(webPage, pbstTest, holder, PatternEnum.SPOOFING_AL);
    }

}
