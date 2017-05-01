package org.feup.ses.pbst.patternTests;

import java.io.Serializable;

public class UrlInfo implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private String url;
    private Boolean publicAccess;
    private boolean firstTry = true;

    public UrlInfo(String url) {
        this.url = url;
    }

    public String getUrl() {
        String u = url == null ? null : url.trim();
        return "".equals(u) ? null : u;
    }

    public String getUrlWithoutParameters() {
        if (url != null && url.contains("?")) {
            String[] params = url.substring(url.indexOf("?") + 1).split("&");
            StringBuilder builder = new StringBuilder("");
            for (String s : params) {
                if (s.indexOf("=") > 0) {
                    builder.append("_");
                    builder.append(s.substring(0, s.indexOf("=")));
                }
            }
            return url.substring(0, url.indexOf("?")) + builder.toString();
        }
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Boolean getPublicAccess() {
        return publicAccess;
    }

    public void setPublicAccess(Boolean publicAccess) {
        this.publicAccess = publicAccess;
    }

    public boolean isFirstTry() {
        return firstTry;
    }

    public void setFirstTry(boolean firstTry) {
        this.firstTry = firstTry;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((url == null) ? 0 : url.hashCode());
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

        UrlInfo other = (UrlInfo) obj;

        if (this.url == null) {
            if (other.getUrl() != null) {
                return false;
            }
        } else if (!this.url.equals(other.getUrl())) {
            return false;
        }

        return true;
    }
}
