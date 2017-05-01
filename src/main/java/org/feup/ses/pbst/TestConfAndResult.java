package org.feup.ses.pbst;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.GUI.widgets.CheckBoxPBST;
import org.feup.ses.pbst.Utils.ConcurrentUrlTreeMap;
import org.feup.ses.pbst.patternTests.UrlInfo;
import org.feup.ses.pbst.patternTests.WebPage;

public class TestConfAndResult implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private String loginPage;
    private String homePage;
    private String failPage;
    private Map<String, Boolean> patterns;
    private List<AccessCredential> credentials;
    private Integer totalDiscovered = 0;
    private Integer totalSelectedToBeTested = 0;
    private Integer totalPublic = 0;
    private Integer totalPrivate = 0;
    private Integer totalNotAccessible = 0;
    private Integer totalAccessed = 0;

    private Integer totalPublicTested = 0;
    private Integer totalPrivateTested = 0;

    private Map<String, WebPage> webPages;

//	private Set<String> totalUrlsDiscovered;
    private ConcurrentUrlTreeMap totalUrlsDiscovered;
    private Queue<UrlInfo> urlsToProcess;
    private Queue<UrlInfo> urlsToTest;
    private List<String> publicUrlsToTest;
    private List<String> privateUrlsToTest;

    private List<UrlInfo> publicUrlsTested;
    private List<UrlInfo> privateUrlsTested;

    private transient CheckBoxPBST guiPatterns;

    public TestConfAndResult() {
    }

    public CheckBoxPBST getGuiPatterns() {
        return guiPatterns;
    }

    public void clear() {
        loginPage = "";
        homePage = "";
        failPage = "";
        if (patterns != null) {
            patterns.clear();
        }
        if (credentials != null) {
            credentials.clear();
        }

        totalDiscovered = 0;
        totalSelectedToBeTested = 0;
        totalPublic = 0;
        totalPrivate = 0;
        totalNotAccessible = 0;
        totalAccessed = 0;

        totalPublicTested = 0;
        totalPrivateTested = 0;

        if (webPages != null) {
            webPages.clear();
        }

        if (totalUrlsDiscovered != null) {
            totalUrlsDiscovered.clear();
        }
        if (urlsToProcess != null) {
            urlsToProcess.clear();
        }
        if (urlsToTest != null) {
            urlsToTest.clear();
        }
        if (publicUrlsToTest != null) {
            publicUrlsToTest.clear();
        }
        if (privateUrlsToTest != null) {
            privateUrlsToTest.clear();
        }

        if (publicUrlsTested != null) {
            publicUrlsTested.clear();
        }
        if (privateUrlsTested != null) {
            privateUrlsTested.clear();
        }
    }

    public void setGuiPatterns(CheckBoxPBST guiPatterns) {
        this.guiPatterns = guiPatterns;
    }

    public String getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(String loginPage) {
        this.loginPage = loginPage;
    }

    public String getHomePage() {
        return homePage;
    }

    public void setHomePage(String homePage) {
        this.homePage = homePage;
    }

    public String getFailPage() {
        return failPage;
    }

    public void setFailPage(String failPage) {
        this.failPage = failPage;
    }

    public void updatePattern(String name, boolean value) {
        patterns.put(name, value);
    }

    public Map<String, Boolean> getPatterns() {
        return patterns;
    }

    public boolean hasPatternsCheckedToTest() {
        if (patterns == null || patterns.values() == null || patterns.values().isEmpty()) {
            return false;
        }

        for (Boolean b : patterns.values()) {
            if (b.booleanValue()) {
                return true;
            }
        }

        return false;
    }

    public boolean isToTestLockout() {
        return hasPatternsCheckedToTest()
                && patterns.get(PatternEnum.SPOOFING_AL.getLiteral()) != null
                && patterns.get(PatternEnum.SPOOFING_AL.getLiteral()).booleanValue();
    }

    public void setPatterns(Map<String, Boolean> patterns) {
        this.patterns = patterns;
    }

    public void setPatterns(CheckBoxPBST allPatterns) {
        if (patterns == null) {
            patterns = new HashMap<String, Boolean>();
        }
        loadPatterns(allPatterns.getChilds());
    }

    private void loadPatterns(List<CheckBoxPBST> childs) {
        if (childs != null && !childs.isEmpty()) {
            for (CheckBoxPBST pattern : childs) {
                patterns.put(pattern.getName(), pattern.getButton().isSelected());
                loadPatterns(pattern.getChilds());
            }
        }
    }

    public List<AccessCredential> getCredentials() {
        return credentials;
    }

    public void setCredentials(List<AccessCredential> credentials) {
        this.credentials = credentials;
    }

    public Integer getTotalDiscovered() {
        return totalDiscovered;
    }

    public void setTotalDiscovered(Integer totalDiscovered) {
        this.totalDiscovered = totalDiscovered;
    }

    public Integer getTotalSelectedToBeTested() {
        return totalSelectedToBeTested;
    }

    public void setTotalSelectedToBeTested(Integer totalSelectedToBeTested) {
        this.totalSelectedToBeTested = totalSelectedToBeTested;
    }

    public Integer getTotalPublic() {
        return totalPublic;
    }

    public void setTotalPublic(Integer totalPublic) {
        this.totalPublic = totalPublic;
    }

    public Integer getTotalPrivate() {
        return totalPrivate;
    }

    public void setTotalPrivate(Integer totalPrivate) {
        this.totalPrivate = totalPrivate;
    }

    public Integer getTotalNotAccessible() {
        return totalNotAccessible;
    }

    public void setTotalNotAccessible(Integer totalNotAccessible) {
        this.totalNotAccessible = totalNotAccessible;
    }

    public Integer getTotalPublicTested() {
        return totalPublicTested;
    }

    public void setTotalPublicTested(Integer totalPublicTested) {
        this.totalPublicTested = totalPublicTested;
    }

    public Integer getTotalPrivateTested() {
        return totalPrivateTested;
    }

    public void setTotalPrivateTested(Integer totalPrivateTested) {
        this.totalPrivateTested = totalPrivateTested;
    }

//	public Set<String> getTotalUrlsDiscovered() {
//		return totalUrlsDiscovered;
//	}
//
//	public void setTotalUrlsDiscovered(Set<String> totalUrlsDiscovered) {
//		this.totalUrlsDiscovered = totalUrlsDiscovered;
//	}
    public ConcurrentUrlTreeMap getTotalUrlsDiscovered() {
        return totalUrlsDiscovered;
    }

    public void setTotalUrlsDiscovered(ConcurrentUrlTreeMap totalUrlsDiscovered) {
        this.totalUrlsDiscovered = totalUrlsDiscovered;
    }

    public Queue<UrlInfo> getUrlsToProcess() {
        return urlsToProcess;
    }

    public void setUrlsToProcess(Queue<UrlInfo> urlsToProcess) {
        this.urlsToProcess = urlsToProcess;
    }

    public Queue<UrlInfo> getUrlsToTest() {
        return urlsToTest;
    }

    public void setUrlsToTest(Queue<UrlInfo> urlsToTest) {
        this.urlsToTest = urlsToTest;
    }

    public List<String> getPublicUrlsToTest() {
        return publicUrlsToTest;
    }

    public void setPublicUrlsToTest(List<String> publicUrlsToTest) {
        this.publicUrlsToTest = publicUrlsToTest;
    }

    public List<String> getPrivateUrlsToTest() {
        return privateUrlsToTest;
    }

    public void setPrivateUrlsToTest(List<String> privateUrlsToTest) {
        this.privateUrlsToTest = privateUrlsToTest;
    }

    public List<UrlInfo> getPublicUrlsTested() {
        return publicUrlsTested;
    }

    public void setPublicUrlsTested(List<UrlInfo> publicUrlsTested) {
        this.publicUrlsTested = publicUrlsTested;
    }

    public List<UrlInfo> getPrivateUrlsTested() {
        return privateUrlsTested;
    }

    public void setPrivateUrlsTested(List<UrlInfo> privateUrlsTested) {
        this.privateUrlsTested = privateUrlsTested;
    }

    public Integer getTotalAccessed() {
        return totalAccessed;
    }

    public void setTotalAccessed(Integer totalAccessed) {
        this.totalAccessed = totalAccessed;
    }

    public Map<String, WebPage> getWebPages() {
        return webPages;
    }

    public void setWebPages(Map<String, WebPage> webPages) {
        this.webPages = webPages;
    }
}
