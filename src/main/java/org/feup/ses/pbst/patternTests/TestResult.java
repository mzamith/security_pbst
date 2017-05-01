package org.feup.ses.pbst.patternTests;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import javafx.scene.image.ImageView;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;

public class TestResult implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private String url;
    private PatternEnum pattern;
    private TestResultEnum state;
    private List<Vulnerability> vulnerabilities;

    private transient ImageView stateImage;

    public TestResult(String url, PatternEnum pattern, TestResultEnum state) {
        super();
        this.url = url;
        this.pattern = pattern;
        this.state = state;

        if (this.vulnerabilities == null) {
            this.vulnerabilities = new ArrayList<Vulnerability>();
        }

        setStateImage();
    }

    public void addVulnerability(String name, String explanation) {
        this.vulnerabilities.add(new Vulnerability(name, explanation));
    }

    public void addVulnerability(Vulnerability vulnerability) {
        this.vulnerabilities.add(vulnerability);
    }

    private void setStateImage() {
        if (state != null) {
            if (state.equals(TestResultEnum.NOT_TESTED)) {
                stateImage = new ImageView("/images/notTested.png");
            } else if (state.equals(TestResultEnum.SECURE)) {
                stateImage = new ImageView("/images/secure.png");
            } else if (state.equals(TestResultEnum.VULNERABLE)) {
                stateImage = new ImageView("/images/vulnerable.png");
            }
        }
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public TestResultEnum getState() {
        return state;
    }

    public void setState(TestResultEnum state) {
        if (this.state == null || this.state.getValue() < state.getValue()) {
            this.state = state;
        }

        setStateImage();
    }

    public ImageView getStateImage() {
        return stateImage;
    }

    public PatternEnum getPattern() {
        return pattern;
    }

    public void setPattern(PatternEnum pattern) {
        this.pattern = pattern;
    }

    public List<Vulnerability> getVulnerabilities() {
        return vulnerabilities;
    }

    public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
        this.vulnerabilities = vulnerabilities;
    }

}
