package org.feup.ses.pbst.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.FormValuesHolder;

public class Utils {

    public static String USER_AGENT = "Mozilla/5.0";

    public static String readBody(String page) {
        StringBuilder builder = new StringBuilder();

        int begin = page.toLowerCase().indexOf("<body");
        if (begin == -1) {
            return null;
        }

        int end = page.toLowerCase().indexOf("</body>");
        if (end == -1) {
            return null;
        }

        String temp = page.substring(begin, end);

        for (int i = 0; i < temp.length(); i++) {
            if (temp.charAt(i) == '<' && temp.charAt(i + 1) != '/') {
                builder.append("\n");
            }
            builder.append(temp.charAt(i));
        }

        return builder.toString();
    }

    public static String readEncodingFromIS(final InputStream is) {
        String charset = null;
        try {
            String temp = IOUtils.toString(is, "UTF-8");

            if (temp.toLowerCase().indexOf("charset=") != -1) {
                temp = temp.substring(temp.toLowerCase().indexOf("charset=") + ("charset=".length()));
                int index1 = temp.indexOf(";") < 0 ? temp.length() : temp.indexOf(";");
                int index2 = temp.indexOf(" ") < 0 ? temp.length() : temp.indexOf(" ");
                int index3 = temp.indexOf("\"") < 0 ? temp.length() : temp.indexOf("\"");
                int endIndex = Math.min(index1, Math.min(index2, index3));
                charset = temp.substring(0, endIndex);
            }
        } catch (IOException e) {
            System.out.println("LOAD PAGE - ERROR getting encoding");
            e.printStackTrace();
        }

        return charset;
    }

    public static String cleanLink(String link, String encoding) {
        if (link.contains("\n") || link.contains("\r")) {
            link = link.replaceAll("\n", "").replaceAll("\r", "");
        }

        link = link.trim();

        try {
            link = URLDecoder.decode(link, encoding);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return link;
    }

    public static String getCompleteLink(String link, String protocol, int port, String host, String path) {
        if (!link.contains("http")) {
            if (link.startsWith("/")) {
                link = protocol + "://" + host + (port > -1 ? ":" + port : "") + link;
            } else {
                link = protocol + "://" + host + (port > -1 ? ":" + port : "") + path + link;
            }
        }

        link = link.replaceAll("&amp;", "&");

        return link;
    }

    public static String extractParameterValue(String form, String parameter) {
        if (form == null || parameter == null || form.toLowerCase().indexOf(parameter.toLowerCase() + "=\"") < 0) {
            return null;
        }
        String key = parameter.toLowerCase() + "=\"";

        String toExtract = form.substring(form.indexOf(key) + key.length());
        toExtract = toExtract.substring(0, toExtract.indexOf("\""));

        return toExtract;
    }

    public static HttpPost createPost(String url, HttpEntity entity) {
        HttpPost post = new HttpPost(url);
        post.setHeader("User-Agent", USER_AGENT);

        post.setEntity(entity);

        return post;
    }

    public static HttpGet createGet(String url, String inputUsername, String username, String inputPassword, String password) {
        HttpGet get = new HttpGet(url + "?" + inputUsername + "=" + username + "&" + inputPassword + "=" + password);
        get.setHeader("User-Agent", USER_AGENT);

        return get;
    }

    public static String getClassNameFormated(Object obj) {
        String className = obj.toString();
        if (className.lastIndexOf(".") > 0) {
            className = className.substring(obj.toString().lastIndexOf(".") + 1);
        }
        boolean changes = className != null;
        int index = 0;
        while (changes) {
            changes = false;
            for (int i = index; i < className.length() - 1; i++) {
                if (className.toUpperCase().charAt(i) != className.charAt(i) && className.toUpperCase().charAt(i + 1) == className.charAt(i + 1)) {
                    index = i + 1;
                    changes = true;
                    break;
                }
            }
            if (changes) {
                className = className.substring(0, index) + " " + className.substring(index);
            }
        }

        return className;
    }

    public static boolean login(TestConfAndResult pbstTest, FormValuesHolder holder, String username, String password) {
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
                    return true;
                }
            }
            if (statusCode == 301 || statusCode == 302) {
                Header url = response.getLastHeader("Location");

                if (url != null && !url.equals(pbstTest.getFailPage()) && !url.equals(pbstTest.getLoginPage())) {
                    return true;
                }
            }
        } catch (IOException e) {
            return false;
        }

        return false;
    }
}
