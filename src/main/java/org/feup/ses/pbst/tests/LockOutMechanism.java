package org.feup.ses.pbst.tests;

import java.util.concurrent.atomic.AtomicInteger;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.Utils.Utils;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;

public class LockOutMechanism extends Test {

    private static long id = 0;
    private static AtomicInteger lockedAfter = new AtomicInteger(0);

    private long myId = 0;

    public LockOutMechanism() {
        super();
    }

    public void test(WebPage webPage, TestConfAndResult pbstTest, FormValuesHolder holder, PatternEnum pattern) {
        super.setWebPage(webPage);

        myId = ++id;

        if (holder != null && holder.getAction() != null) {

            if (holder.getInputUsername() != null && !"".equals(holder.getInputUsername())
                    && holder.getInputPassword() != null && !"".equals(holder.getInputUsername())) {

                String[] invalidPasswords = {"passwordTest", "testPassword", "123321", "1357908642"};
                String invalidPassword = null;
                String username = pbstTest.getCredentials().get(0).getUsername();
                String password = pbstTest.getCredentials().get(0).getPassword();

                //Do a valid login to test if is not already locked
                if (Utils.login(pbstTest, holder, username, password)) {

                    //Select a invalid password
                    int count = 0;
                    while (count < invalidPasswords.length) {
                        invalidPassword = invalidPasswords[count++];
                        if (!Utils.login(pbstTest, holder, username, invalidPassword)) {
                            break;
                        }
                    }

                    //Do a valid login before start testing lockout
                    Utils.login(pbstTest, holder, username, password);

                    for (int i = 0; i < 3; i++) {
                        Utils.login(pbstTest, holder, username, invalidPassword);
                    }

                    //Do a valid login to test if is locked after 3 invalid passwords
                    if (Utils.login(pbstTest, holder, username, password)) {

                        for (int i = 0; i < 4; i++) {
                            Utils.login(pbstTest, holder, username, invalidPassword);
                        }

                        //Do a valid login to test if is locked after 4 invalid passwords
                        if (Utils.login(pbstTest, holder, username, password)) {

                            for (int i = 0; i < 5; i++) {
                                Utils.login(pbstTest, holder, username, invalidPassword);
                            }
                            //Do a valid login to test if is locked after 5 invalid passwords
                            if (Utils.login(pbstTest, holder, username, password)) {
                                webPage.addTestResult(pattern, TestResultEnum.VULNERABLE, "Lookout Mechanism", "Account does not became locked out after 5 wrongs passwords in sequence");
                            } else {
                                lockedAfter.set(5);
                                webPage.addTestResult(pattern, TestResultEnum.SECURE);
                            }
                        } else {
                            lockedAfter.set(4);
                            webPage.addTestResult(pattern, TestResultEnum.SECURE);
                        }
                    } else {
                        lockedAfter.set(3);
                        webPage.addTestResult(pattern, TestResultEnum.SECURE);
                    }
                } else {
                    if (lockedAfter.get() >= 3 && lockedAfter.get() <= 5) {
                        webPage.addTestResult(pattern, TestResultEnum.SECURE);
                    } else {
                        webPage.addTestResult(pattern, TestResultEnum.VULNERABLE, "LookOutMechanism", "Account does not became locked out after 5 wrongs passwords in sequence");
                    }
                }
            }
        } else {
            webPage.addTestResult(pattern, TestResultEnum.SECURE);
        }
    }

    public long getMyId() {
        return myId;
    }
}
