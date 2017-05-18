package org.feup.ses.pbst.tests;

import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.feup.ses.pbst.Enums.AuthHeader;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.Utils.Utils;
import org.feup.ses.pbst.patternTests.FormValuesHolder;
import org.feup.ses.pbst.patternTests.WebPage;

import javax.rmi.CORBA.Util;
import java.util.*;
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

    private String loginTitle;

    public CheckTokens() {
        super();
    }

    public void test(WebPage webPage, TestConfAndResult pbstTest, FormValuesHolder holder, PatternEnum pattern){
        super.setWebPage(webPage);

        boolean vulnerable;
        boolean hasTokenHeader = false;

        myId = ++id;
        //Utils.makeRequest();
        //Map<WebPage.HeaderKey, List<String>> headersMap = webPage.getHeaders();
       // List<String> l = headersMap.keySet().stream().map(WebPage.HeaderKey::getHeader).collect(Collectors.toList());

        String username = pbstTest.getCredentials().get(0).getUsername();
        String password = pbstTest.getCredentials().get(0).getPassword();

        HttpResponse login = Utils.makeRequest(pbstTest.getLoginPage(), null, null);
        loginTitle = getTitle(login);

        HttpResponse r = Utils.loginWithResponse(pbstTest, holder, username, password);

        // 1. After making a successful login, we check to see if the reponse has one of the following headers:
        // - Set-Cookie - Save token in cookies
        // - Authorization - Token can also be sent in this header

        // 2. If this condition is met, we make an authenticated request to the website. This will allow us
        // to determine if the token can successfully identify the user and grant him privileges.

        // 3. If this condition is met, we make sure the user does not have this privileges if the
        // token is taken out of the request.

        if (r != null)
        hasTokenHeader = Arrays.asList(r.getAllHeaders()).stream()
                                        .map(Header::getName)
                                        .anyMatch((header) -> header.equals("Set-Cookie") || header.equals("Authorization"));

        if (hasTokenHeader && hasCookie(r)) {
            // get the token from the response.
            vulnerable = (getCookies(r).contains(username) || getCookies(r).contains(password));
            HttpResponse authResponse = Utils.makeRequest(pbstTest.getHomePage(), getCookies(r), AuthHeader.COOKIE);

            if (verifyLoginRedirect(authResponse, pbstTest)) vulnerable = true;

            HttpResponse notAuthResponse = Utils.makeRequest(pbstTest.getHomePage(), null, AuthHeader.COOKIE);

            if (!verifyLoginRedirect(notAuthResponse, pbstTest)) vulnerable = true;


        }else if (hasTokenHeader && hasAuthHeader(r)){
            vulnerable = (getAuth(r).contains(username) || getAuth(r).contains(password));

            HttpResponse re = Utils.makeRequest(pbstTest.getHomePage(), getAuth(r), AuthHeader.AUTHORIZATION);

            if (verifyLoginRedirect(re, pbstTest)) vulnerable = true;

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
                .map(header -> header.getValue().split("; ")[0])
                .collect(Collectors.joining("; "));
    }

    private String getAuth(HttpResponse response){

        return Arrays.asList(response.getAllHeaders()).stream()
                .filter(header -> header.getName().equals(AUTH_HEADER))
                .map(header -> header.getValue().split(";")[0])
                .findFirst().get();

    }

    private boolean verifyLoginRedirect(HttpResponse response, TestConfAndResult pbstTest){

        String body = Utils.getBody(response);
        Header redirect = response.getLastHeader("Location");

        //if the response does not have a body tag, it is probably a redirect
        return (!body.contains("<body") ||
                (redirect != null && redirect.getValue().equals(getPbstTest().getLoginPage())) ||
                (redirect != null && redirect.getValue().equals(pbstTest.getFailPage())) ||
                getTitle(body).equals(loginTitle));
    }

    private String getTitle(HttpResponse response){

        String body = Utils.getBody(response);
        if (body == null) return "";

        String title = body.substring(body.indexOf("<title>") + 7, body.indexOf("</title>"));
        return title;
    }

    private String getTitle(String response){

        String title = response.substring(response.indexOf("<title>") + 7, response.indexOf("</title>"));
        return title;
    }
}
