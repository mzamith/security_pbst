package org.feup.ses.pbst.patternTests;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.swing.text.html.HTML.Tag;
import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.Utils.Utils;

public class WebPage implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;
    public static final String STATUS = "Status";
    public static final String CHARSET = "charset";

    private String urlLoginPage;
    private String urlHomePage;
    private String urlPath;
    private String protocol;
    private String host;
    private int port;
    private String path;
    private String encoding;
    private String page;
    private int statusCode;
    private String urlResult;
    private boolean needsAuthentication;
    private Map<HeaderKey, List<String>> headers;
    private Map<PatternEnum, TestResult> testResults;
    private String inputUsernameParameterName;
    private String inputPasswordParameterName;
    private boolean vulnerable = false;
    private List<Vulnerability> vulnerabilities;

    private transient URL url;
    private transient URLConnection pageConnection;

    private transient String doctype;
    private transient String htmlInfo;
    private transient Map<String, List<String>> headMap;
    private transient String title;
    private transient List<String> scripts;
    private transient List<String> styles;
    private transient Set<String> links;
    private transient Set<String> imageLinks;
    private transient Set<String> documentLinks;
    private transient Set<String> styleLinks;
    private transient Map<String, List<String>> forms;
    private transient String body;
    private transient List<String> comments;

    private String[] wordsToSearch = new String[]{"query", "user", "pass", "credentials", "admin"};

    public WebPage(final String urlPath, final String urlHomePage, final String urlLoginPage) {
        this.urlPath = urlPath;
        this.urlLoginPage = urlLoginPage;
        this.urlHomePage = urlHomePage;

        if (urlHomePage != null && urlLoginPage != null && urlLoginPage.equals(urlHomePage)) {
            this.urlLoginPage = null;
        }

        try {
            this.url = new URL(urlPath);
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }

        this.headers = new HashMap<HeaderKey, List<String>>();
        this.headMap = new HashMap<String, List<String>>();
        this.scripts = new ArrayList<String>();
        this.styles = new ArrayList<String>();
        this.links = new LinkedHashSet<String>();
        this.imageLinks = new LinkedHashSet<String>();
        this.documentLinks = new LinkedHashSet<String>();
        this.styleLinks = new LinkedHashSet<String>();
        this.forms = new HashMap<String, List<String>>();
        this.comments = new ArrayList<String>();
        this.testResults = new LinkedHashMap<PatternEnum, TestResult>();

        loadTestResults();
    }

    public boolean openConnection(int timeout) {
        if (url == null) {
            return false;
        }
        try {
//			System.out.println("URL: "+url);
            pageConnection = url.openConnection();
            pageConnection.setRequestProperty("User-Agent", Utils.USER_AGENT);
            pageConnection.setConnectTimeout(timeout);
            readHeaders();
            readHostAndPath();
            return true;
        } catch (NullPointerException | IOException e) {
            System.out.println("ERROR ON OPEN CONNECTION: " + url);
            e.printStackTrace();
        }

        return false;
    }

    public boolean loadPage() {

        try {

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            urlResult = pageConnection.getURL().toString();

            InputStream is = pageConnection.getInputStream();

            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) > -1) {
                baos.write(buffer, 0, len);
            }
            baos.flush();
            InputStream is1 = new ByteArrayInputStream(baos.toByteArray());
            InputStream is2 = new ByteArrayInputStream(baos.toByteArray());

            if (encoding == null) {
                encoding = pageConnection.getContentEncoding();

                if (encoding == null) {
                    encoding = Utils.readEncodingFromIS(is1);
                }
            }
            encoding = (encoding == null) ? "UTF-8" : encoding;
            page = IOUtils.toString(is2, encoding);

            return true;
        } catch (IOException e) {
//			System.out.println("ERROR ON LOAD PAGE");
//			System.out.println(headers);
//			e.printStackTrace();
        }

        return false;
    }

    public void processPage(final TestConfAndResult pbstTest) {
        if (urlLoginPage != null && urlLoginPage.equals(urlResult) && !urlLoginPage.equals(urlPath)) {
            needsAuthentication = true;
        } else {
            needsAuthentication = false;
        }

        if (statusCode == 0 || statusCode == 200) {
            readPage();
        }

        if (needsAuthentication) {
            authenticateAndReprocess(pbstTest, forms);
        }
    }

    private void readPage() {
        if (page != null) {
            readDoctype();
            readHtmlInfo();
            readHead();
//			readRedirectLinks();
            body = Utils.readBody(page);
            extractLinksFromPage();
            if (body != null && !"".equals(body)) {
//				readBodyLinks();
                readBodyForms();
            }
            readComments();
        }
    }

    public void authenticateAndReprocess(final TestConfAndResult pbstTest, final Map<String, List<String>> forms) {
        FormValuesHolder holder = null;
        try {
            holder = new FormValuesHolder(new URL(protocol, host, port, ""), path, forms);
        } catch (MalformedURLException e1) {
            e1.printStackTrace();
        }

        if (holder == null) {
            return;
        }

        String method = holder.getMethod();
        String action = holder.getAction();
        String inputUsername = holder.getInputUsername();
        String inputPassword = holder.getInputPassword();
        String username = holder.getUsername();
        String password = holder.getPassword();

        if (pbstTest != null && pbstTest.getCredentials() != null && !pbstTest.getCredentials().isEmpty()) {
            username = pbstTest.getCredentials().get(0).getUsername();
            password = pbstTest.getCredentials().get(0).getPassword();
        }

        if (inputPassword != null && !"".equals(inputPassword) && inputUsername != null && !"".equals(inputUsername)) {

            try {
                List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
                urlParameters.add(new BasicNameValuePair(inputUsername, username));
                urlParameters.add(new BasicNameValuePair(inputPassword, password));

                HttpEntity entity = new UrlEncodedFormEntity(urlParameters);

                HttpClient client = HttpClientBuilder.create().build();
                HttpResponse response = null;
                HttpPost post = null;
                HttpGet get = null;

                if ("POST".equals(method.toUpperCase())) {
                    post = Utils.createPost(urlLoginPage == null ? action : urlLoginPage, entity);

                    response = client.execute(post);
                } else {
                    get = Utils.createGet(urlLoginPage == null ? action : urlLoginPage, inputUsername, username, inputPassword, password);

                    response = client.execute(get);
                }

                int statusCode = response.getStatusLine().getStatusCode();

                if (statusCode == 400 || statusCode == 404) {
                    return;
                }

                //Needs to authenticate from a loginPage
                if (statusCode == 200 || statusCode == 303 || statusCode == 307) {

                    client = HttpClientBuilder.create().build();
                    try {
                        if (post != null) {
                            post.setURI(new URI(urlLoginPage == null ? urlPath : urlLoginPage));
                            response = client.execute(post);
                        } else if (get != null) {
                            get.setURI(new URI(urlLoginPage == null ? urlPath : urlLoginPage));
                            response = client.execute(get);
                        }
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                        EntityUtils.consume(entity);
                        return;
                    }

                    statusCode = response.getStatusLine().getStatusCode();
                }

                //Login width success and redirected - Lets get the redirected page
                if (statusCode == 301 || statusCode == 302) {

                    Header header = response.getLastHeader("Location");
                    String redirectedURL = null;
                    if (header != null) {
                        redirectedURL = header.getValue();
                    } else {
                        redirectedURL = urlHomePage;
                    }

                    try {
                        if (post != null) {
                            post.setURI(new URI(redirectedURL));
                            response = client.execute(post);
                        } else if (get != null) {
                            get.setURI(new URI(redirectedURL));
                            response = client.execute(get);
                        }
                    } catch (URISyntaxException e) {
                        e.printStackTrace();
                        EntityUtils.consume(entity);
                        return;
                    }

                    statusCode = response.getStatusLine().getStatusCode();

                    processLoadPage(response, redirectedURL);
                    readPage();

                    this.inputUsernameParameterName = inputUsername;;
                    this.inputPasswordParameterName = inputPassword;
                    EntityUtils.consume(entity);
                } else {
                    EntityUtils.consume(entity);
                    return;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void processLoadPage(HttpResponse response, String urlResult) {
        try {

            HttpEntity entity = response.getEntity();

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            InputStream is = response.getEntity().getContent();

            this.urlResult = urlResult;

            byte[] buffer = new byte[1024];
            int len;
            while ((len = is.read(buffer)) > -1) {
                baos.write(buffer, 0, len);
            }
            baos.flush();
            InputStream is1 = new ByteArrayInputStream(baos.toByteArray());
            InputStream is2 = new ByteArrayInputStream(baos.toByteArray());

            encoding = Utils.extractParameterValue(ContentType.getOrDefault(entity).toString(), "charset");
            if (encoding == null) {
                encoding = Utils.readEncodingFromIS(is1);
            }
            encoding = (encoding == null) ? "UTF-8" : encoding;
            page = IOUtils.toString(is2, encoding);

            EntityUtils.consume(entity);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void readHeaders() {
        try {
            Map<String, List<String>> temp = new HashMap<String, List<String>>();
            temp = pageConnection.getHeaderFields();

            headers = new HashMap<HeaderKey, List<String>>();
            for (String key : temp.keySet()) {
                String newKey = (key == null) ? STATUS : key;
                headers.put(new HeaderKey(newKey), temp.get(key));

                if (STATUS.equals(newKey)) {
                    String tmp = temp.get(key) != null && !temp.get(key).isEmpty() ? temp.get(key).get(0) : null;
                    if (tmp != null) {
                        tmp = tmp.substring(tmp.indexOf(" ") + 1);
                        tmp = tmp.substring(0, tmp.indexOf(" "));

                        try {
                            statusCode = Integer.parseInt(tmp);
                        } catch (NumberFormatException nfe) {
                            nfe.printStackTrace();
                            statusCode = 0;
                        }
                    } else {
                        statusCode = 0;
                    }
                }
            }

            for (List<String> list : temp.values()) {
                if (list != null && !list.isEmpty()) {
                    for (String s : list) {
                        if (s.contains(CHARSET)) {
                            encoding = s.substring(s.indexOf(CHARSET) + CHARSET.length() + 1);
                            if (encoding.contains(";")) {
                                encoding = encoding.substring(0, encoding.indexOf(";"));
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
//			System.out.println("ERROR READING HEADERS");
//			e.printStackTrace();
        }
    }

    public void readHostAndPath() {
        protocol = pageConnection.getURL().getProtocol();
        host = pageConnection.getURL().getHost();
        port = pageConnection.getURL().getPort();
        path = pageConnection.getURL().getPath();
        if (path.contains("/")) {
            path = path.substring(0, path.lastIndexOf("/")) + "/";
        }
    }

    private void readDoctype() {
        String temp = page;

        int begin = temp.toLowerCase().indexOf("<!doctype");
        if (begin == -1) {
            return;
        }

        temp = temp.substring(begin);
        int end = temp.indexOf(">");
        if (end == -1) {
            return;
        }

        doctype = page.substring(begin, end + 1);
    }

    private void readHtmlInfo() {
        String temp = page;
        try {
            int begin = temp.toLowerCase().indexOf("<html");
            if (begin > 0) {
                temp = temp.substring(begin);
                int end = begin + temp.indexOf(">") + 1;

                htmlInfo = page.substring(begin, end);
            }
        } catch (StringIndexOutOfBoundsException ex) {
            ex.printStackTrace();
        }
    }

    private void readHead() {
        String temp = page;

        int begin = temp.toLowerCase().indexOf("<head");
        if (begin == -1) {
            return;
        }

        int end = temp.toLowerCase().indexOf("</head>");
        if (end == -1) {
            return;
        }

        temp = temp.substring(begin + ("<head").length(), end);

        extractToMap(temp, Tag.TITLE.toString().toLowerCase(), headMap);
        extractToMap(temp, Tag.STYLE.toString().toLowerCase(), headMap);
        extractToMap(temp, Tag.BASE.toString().toLowerCase(), headMap);
        extractToMap(temp, Tag.LINK.toString().toLowerCase(), headMap);
        extractToMap(temp, Tag.META.toString().toLowerCase(), headMap);
        extractToMap(temp, Tag.SCRIPT.toString().toLowerCase(), headMap);
    }

    private void extractToMap(String str, String tag, Map<String, List<String>> map) {
        String temp = str;

        while (temp != null) {
            int endLenght = ("</" + tag + ">").length();

            int begin = temp.toLowerCase().indexOf("<" + tag + ">");
            if (begin == -1) {
                begin = temp.toLowerCase().indexOf("<" + tag);
            }

            if (begin > -1) {
                int end = temp.indexOf("</" + tag + ">");
                if (end == -1) {
                    end = temp.indexOf(">");
                    endLenght = 1;
                }

                if (end > -1) {
                    if (end < begin) {
                        temp = temp.substring(end + endLenght + 1);
                    } else {
                        try {
                            String element = temp.substring(begin, end + endLenght);
                            if (map.get(tag) == null) {
                                map.put(tag, new ArrayList<String>());
                            }
                            if (!map.get(tag).contains(element)) {
                                map.get(tag).add(element);
                            }

                            temp = temp.substring(Math.min(end + endLenght + 1, temp.length()));
                        } catch (StringIndexOutOfBoundsException ex) {
                            System.err.println("ERROR ON EXTRACT TO MAP");
                            ex.printStackTrace();
                            break;
                        }
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
    }

    private void extractLinksFromPage() {
        extractLinksFromPage("<meta ", "url");
        extractLinksFromPage("<a ", "href");
        extractLinksFromPage("<area ", "href");
        extractLinksFromPage("<base ", "href");
        extractLinksFromPage("<iframe ", "src");
//		extractLinksFromPage("<link ", "href");
        extractLinksFromPage("<frame ", "src");
    }

    private void extractLinksFromPage(String tag, String parameter) {
        if (body != null && !body.isEmpty()) {

            int beginIndex = 0;
            int endIndex = 0;
            int lastBeginIndex = 0;
            while (beginIndex < body.length()) {
                beginIndex = lastBeginIndex + body.substring(lastBeginIndex).indexOf(parameter);

                if (beginIndex < lastBeginIndex) {
                    break;
                }

                endIndex = beginIndex + body.substring(beginIndex).indexOf(">");

                if (endIndex < beginIndex || endIndex > body.length()) {
                    break;
                }

                processTagContent(body.substring(beginIndex, endIndex), parameter);

                lastBeginIndex = endIndex;
            }
        }
    }

    private void processTagContent(String tag, String parameter) {
        String link = Utils.extractParameterValue(tag, parameter);//temp.substring(0, hrefEnd).toLowerCase();
        if (link != null && !link.startsWith("#") && !link.startsWith("mailto:") && !link.toLowerCase().startsWith("javascript")) {
            if (link.startsWith("\"") || link.startsWith("'")) {
                link = link.substring(1);
            }
            if (link.contains("\"")) {
                link = link.substring(0, link.indexOf("\""));
            }

            link = Utils.getCompleteLink(link, protocol, port, host, path);
            if (link.contains(host)) {
                link = link.substring(link.lastIndexOf("http")).trim();

                link = Utils.cleanLink(link, encoding);

                if (link.toLowerCase().endsWith("jpeg") || link.toLowerCase().endsWith("webp") || link.toLowerCase().endsWith("gif")
                        || link.toLowerCase().endsWith("png") || link.toLowerCase().endsWith("apng") || link.toLowerCase().endsWith("tiff")
                        || link.toLowerCase().endsWith("bmp") || link.toLowerCase().endsWith("xbm") || link.toLowerCase().endsWith("ico")) {
                    imageLinks.add(link);
                } else if (link.toLowerCase().endsWith("pdf") || link.toLowerCase().endsWith("xls") || link.toLowerCase().endsWith("xls")
                        || link.toLowerCase().endsWith("doc") || link.toLowerCase().endsWith("docx") || link.toLowerCase().endsWith("ppt")
                        || link.toLowerCase().endsWith("pptx") || link.toLowerCase().endsWith("xml") || link.toLowerCase().endsWith("rss")
                        || link.toLowerCase().endsWith("atom")) {
                    documentLinks.add(link);
                } else if (link.toLowerCase().endsWith("css") || link.toLowerCase().endsWith("js")) {
                    styleLinks.add(link);
                } else {
                    links.add(link);
                }
            }
        }
    }

    private void readBodyForms() {
        forms.clear();

        try {
            int begin = body.indexOf("<form");
            if (begin == -1) {
                return;
            }

            String temp = body.substring(begin);

            while (temp != null) {
                begin = temp.toLowerCase().indexOf("<form");
                int end = temp.toLowerCase().indexOf("</form>");

                if (begin < 0) {
                    break;
                }

                String form = temp.substring(begin, end + 7);

                if (form.toLowerCase().contains("<form>")) {
                    String link = Utils.extractParameterValue(form, "formaction");
                    link = Utils.getCompleteLink(link, protocol, port, host, path);

                    if (!links.contains(link)) {
                        links.add(link);
                    }
                } else {
                    String formKey = form.substring(0, form.indexOf(">") + 1);

                    if (formKey.contains("action=\"/")) {
                        formKey = formKey.substring(0, formKey.indexOf("action=\"/")) + "action=\"" + urlPath
                                + formKey.substring(formKey.indexOf("action=\"/") + ("action=\"").length());

                        String link = Utils.extractParameterValue(form, "action");
                        link = Utils.getCompleteLink(link, protocol, port, host, path);

                        if (!links.contains(link)) {
                            links.add(link);
                        }
                    }

                    forms.put(formKey, new ArrayList<String>());
                    String inputs = form;

                    while (inputs != null) {
                        int beginInput = inputs.toLowerCase().indexOf("<input");
                        if (beginInput < 0) {
                            break;
                        }

                        inputs = inputs.substring(beginInput);
                        int endInput = inputs.toLowerCase().indexOf(">") + 1;

                        String input = inputs.substring(0, endInput);
                        forms.get(formKey).add(input);

                        inputs = inputs.substring(endInput + 1);
                    }
                }

                temp = temp.substring(end + 7);
            }
        } catch (StringIndexOutOfBoundsException ex) {
            System.out.println("READ BODY FORMS");
            ex.printStackTrace();
        }
    }

    private void readComments() {
        String temp = page;
        while (temp != null) {
            int begin = temp.indexOf("<!--");
            if (begin < 0) {
                break;
            }
            int end = temp.indexOf("-->");
            if (end < 0) {
                break;
            }

            String comment = temp.substring(begin, end + 3);
            for (String s : wordsToSearch) {
                if (comment.contains(s)) {
                    comments.add(comment);
                    break;
                }
            }

            temp = temp.substring(end + 3);
        }
    }

    public URL getUrl() {
        return url;
    }

    public URLConnection getPageConnection() {
        return pageConnection;
    }

    public String getPage() {
        return page;
    }

    public Map<HeaderKey, List<String>> getHeaders() {
        return headers;
    }

    public String getDoctype() {
        return doctype;
    }

    public String getHtmlInfo() {
        return htmlInfo;
    }

    public Map<String, List<String>> getHeadMap() {
        return headMap;
    }

    public String getTitle() {
        return title;
    }

    public List<String> getScripts() {
        return scripts;
    }

    public List<String> getStyles() {
        return styles;
    }

    public Set<String> getLinks() {
        return links;
    }

    public Map<String, List<String>> getForms() {
        return forms;
    }

    public String getBody() {
        return body;
    }

    public String getUrlPath() {
        return urlPath;
    }

    public String getUrlResult() {
        return urlResult;
    }

    public boolean isNeedsAuthentication() {
        return needsAuthentication;
    }

    public List<String> getComments() {
        return comments;
    }

    public void addTestResult(PatternEnum pattern, TestResultEnum state) {
        testResults.get(pattern).setState(state);
    }

    public void addTestResult(PatternEnum pattern, TestResultEnum state, String vulnerabilityName, String vulnerabilityExplanation) {
        testResults.get(pattern).setState(state);
        Vulnerability vulnerability = new Vulnerability(vulnerabilityName, vulnerabilityExplanation);
        testResults.get(pattern).addVulnerability(vulnerability);
        vulnerable = true;
        if (vulnerabilities == null) {
            vulnerabilities = new ArrayList<Vulnerability>();
        }
        if (!vulnerabilities.contains(vulnerability)) {
            vulnerabilities.add(vulnerability);
        }
    }

    public Map<PatternEnum, TestResult> getTestResults() {
        return testResults;
    }

    public TestResult getTestResults(PatternEnum pattern) {
        return testResults.get(pattern);
    }

    public String getEncoding() {
        return encoding;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getInputUsernameParameterName() {
        return inputUsernameParameterName;
    }

    public String getInputPasswordParameterName() {
        return inputPasswordParameterName;
    }

    public Set<String> getImageLinks() {
        return imageLinks;
    }

    public Set<String> getDocumentLinks() {
        return documentLinks;
    }

    public boolean isVulnerable() {
        return vulnerable;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((host == null) ? 0 : host.hashCode());
        result = prime * result + ((path == null) ? 0 : path.hashCode());
        result = prime * result + port;
        result = prime * result + ((protocol == null) ? 0 : protocol.hashCode());
        result = prime * result + ((urlPath == null) ? 0 : urlPath.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        WebPage other = (WebPage) obj;
        if (host == null) {
            if (other.host != null) {
                return false;
            }
        } else if (!host.equals(other.host)) {
            return false;
        }
        if (path == null) {
            if (other.path != null) {
                return false;
            }
        } else if (!path.equals(other.path)) {
            return false;
        }
        if (port != other.port) {
            return false;
        }
        if (protocol == null) {
            if (other.protocol != null) {
                return false;
            }
        } else if (!protocol.equals(other.protocol)) {
            return false;
        }
        if (urlPath == null) {
            if (other.urlPath != null) {
                return false;
            }
        } else if (!urlPath.equals(other.urlPath)) {
            return false;
        }
        return true;
    }

    public class HeaderKey implements Serializable {

        /**
         *
         */
        private static final long serialVersionUID = 1L;

        String header;

        public HeaderKey(String header) {
            this.header = header;
        }

        public String getHeader() {
            return header;
        }

        public void setHeader(String header) {
            this.header = header;
        }
    }

    private void loadTestResults() {
        for (PatternEnum pattern : PatternEnum.VALUES) {
            testResults.put(pattern, new TestResult(urlPath, pattern, TestResultEnum.NOT_TESTED));
        }
    }

}
