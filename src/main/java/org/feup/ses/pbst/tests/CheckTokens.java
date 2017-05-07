package org.feup.ses.pbst.tests;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.Utils.Utils;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;

import javax.rmi.CORBA.Util;
import java.util.*;
import java.util.stream.Collector;
import java.util.stream.Collectors;

/**
 * Created by mzamith on 06/05/2017.
 */
public class CheckTokens extends Test {

    private final String COOKIE_HEADER_RESPONSE = "Set-Cookie";
    private final String COOKIE_HEADER_REQUEST = "Cookie";
    private final String AUTH_HEADER = "Authorization";

    private static long id = 0;
    private long myId = 0;

    public CheckTokens() {
        super();
    }

    public void test(WebPage webPage, TestConfAndResult pbstTest, FormValuesHolder holder, PatternEnum pattern){
        super.setWebPage(webPage);

        boolean vulnerable  = false;
        boolean hasTokenHeader = false;

        myId = ++id;

        Map<WebPage.HeaderKey, List<String>> headersMap = webPage.getHeaders();
        List<String> l = headersMap.keySet().stream().map(WebPage.HeaderKey::getHeader).collect(Collectors.toList());

        String username = "up201607826";
        String password = "2JxYKJMEH";

        HttpResponse r = Utils.loginWithResponse(pbstTest, holder, "up201607826", "2JxYKJMEH");

        // 1. After making a successful login, we check to see if the reponse has one of the following headers:
        // - Set-Cookie - Save token in cookies
        // - Authorization - Token can also be sent in this header

        if (r != null)
        hasTokenHeader = Arrays.asList(r.getAllHeaders()).stream()
                                        .map(Header::getName)
                                        .anyMatch((header) -> header.equals("Set-Cookie") || header.equals("Authorization"));

        if (hasTokenHeader && hasCookie(r)) {
            // get the token from the response.
            vulnerable = (getCookies(r).contains(username) || getCookies(r).contains(password));
        }else if (hasTokenHeader && hasAuthHeader(r)){
            vulnerable = (getAuth(r).contains(username) || getAuth(r).contains(password));

        } else {
            vulnerable = true;
        }

        if (vulnerable) {
            webPage.addTestResult(pattern, TestResultEnum.VULNERABLE, "Credential Tokenizer", "Missing header x-frame-options");
        } else {
            webPage.addTestResult(pattern, TestResultEnum.SECURE);
        }
    }

    private boolean hasCookie(HttpResponse response){

        return Arrays.asList(response.getAllHeaders()).stream()
                .map(Header::getName)
                .anyMatch((header) -> header.equals(COOKIE_HEADER_RESPONSE));
    }

    private boolean hasAuthHeader(HttpResponse response){
        return Arrays.asList(response.getAllHeaders()).stream()
                .map(Header::getName)
                .anyMatch((header) -> header.equals(AUTH_HEADER));
    }

    private String getCookies(HttpResponse response){

        return Arrays.asList(response.getAllHeaders()).stream()
               .filter(header -> header.getName().equals(COOKIE_HEADER_RESPONSE))
                .map(header -> header.getValue().split(";")[0])
                .collect(Collectors.joining("; "));
    }

    private String getAuth(HttpResponse response){

        return Arrays.asList(response.getAllHeaders()).stream()
                .filter(header -> header.getName().equals(AUTH_HEADER))
                .map(header -> header.getValue().split(";")[0])
                .findFirst().get();

    }
}
