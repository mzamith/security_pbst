package org.feup.ses.pbst.GUI;

import javafx.geometry.Insets;
import javafx.scene.layout.HBox;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;

public class WebEngineTester {

    private WebEngine webEngine;
    private HBox webEngineBox;
    private String url;

    public WebEngineTester(String url) {
        this.url = url;

        WebView browser = createBrowser();
        webEngine = browser.getEngine();
        webEngineBox = createHbox(browser);
    }

    public WebEngine getWebEngine() {
        return webEngine;
    }

    public void setWebEngine(WebEngine webEngine) {
        this.webEngine = webEngine;
    }

    public HBox getWebEngineBox() {
        return webEngineBox;
    }

    public void setWebEngineBox(HBox webEngineBox) {
        this.webEngineBox = webEngineBox;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    private HBox createHbox(WebView browser) {
        HBox hBox = new HBox();
        hBox.setPadding(new Insets(5, 5, 5, 3));
        hBox.setStyle("-fx-background-color: rgba(0.8, 0.8, 0.8, 0.3);");
        hBox.getChildren().add(browser);

        return hBox;
    }

    private WebView createBrowser() {
        WebView browser = new WebView();
        double width = ((GuiTestsConfiguration.WIDTH - 40));
        browser.setMinSize(width, 200);
        browser.setMaxSize(width, 200);
        browser.setVisible(true);

        return browser;
    }

}
