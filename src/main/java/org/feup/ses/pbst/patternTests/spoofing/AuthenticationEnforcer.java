package org.feup.ses.pbst.patternTests.spoofing;

import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;
import org.feup.ses.pbst.tests.Clickjacking;
import org.feup.ses.pbst.tests.CredentialsTransport;
import org.feup.ses.pbst.tests.DefaultCredentials;
import org.feup.ses.pbst.tests.SqlInjection;

public class AuthenticationEnforcer extends Spoofing {

    private Clickjacking clickjacking;
    private CredentialsTransport credentialsTransport;
    private DefaultCredentials defaultCredentials;
    private SqlInjection sqlInjection;

    public void startTests(WebPage webPage, TestConfAndResult pbstTest, FormValuesHolder holder/*ConcurrentLinkedQueue<FormValuesHolder> formsValuesHolderQueue*/) {

        clickjacking = new Clickjacking();
        clickjacking.test(webPage, PatternEnum.SPOOFING_AE);

        credentialsTransport = new CredentialsTransport();
        credentialsTransport.test(webPage, holder, PatternEnum.SPOOFING_AE);

        sqlInjection = new SqlInjection();
        sqlInjection.test(webPage, pbstTest, holder, PatternEnum.SPOOFING_AE);

        defaultCredentials = new DefaultCredentials();
        defaultCredentials.test(webPage, pbstTest, holder, PatternEnum.SPOOFING_AE);

        //TODO - outros testes
    }

}
