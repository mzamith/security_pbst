package org.feup.ses.pbst.GUI;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import javafx.application.Platform;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.geometry.Bounds;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.RadioButton;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.ScrollPane.ScrollBarPolicy;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TabPane.TabClosingPolicy;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.Toggle;
import javafx.scene.control.ToggleGroup;
import javafx.scene.control.Tooltip;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.input.KeyCode;
import javafx.scene.input.KeyCodeCombination;
import javafx.scene.input.KeyCombination;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.scene.web.WebEngine;
import javafx.scene.web.WebView;
import javax.swing.text.html.ImageView;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.patternTests.TestResult;
import org.feup.ses.pbst.patternTests.UrlInfo;
import org.feup.ses.pbst.patternTests.Vulnerability;
import org.feup.ses.pbst.patternTests.WebPage;
import org.feup.ses.pbst.patternTests.WebPage.HeaderKey;

public class GuiTestsRun implements Observer {

    public static final String TAG = "guiTestRun";

    private StackPane workPane;
    private ScrollPane scrollTestRun;
    private GridPane testRun;
    private ObservableList<UrlInfo> publicTableData;
    private ObservableList<UrlInfo> privateTableData;

    private ObservableList<TestResult> testResultsTableData;
    private ObservableList<Vulnerability> vulnerabilitiesTableData;
    private ObservableList<HeaderKey> headersTableData;
    private ToggleGroup group;
    private Button btViewGlobalResult;

    private ConcurrentMap<String, WebPage> webPagesMap;
    private Map<PatternEnum, TestResult> globalTestsResult;
    private TextArea pageSource;
    private WebView browserStyled;
    private WebView browserText;
    private TextArea vulnerabilityInfo;
    private TextArea headerInfo;
    private String selectedURL;
    private AtomicInteger lastIndexReceivedFromPublicUrl;
    private AtomicInteger lastIndexReceivedFromPrivateUrl;

    private WebEngine webEngineStyled;
    private WebEngine webEngineText;

    private Scene scene;

    public GuiTestsRun(final Scene scene, final StackPane workPane) {
        this.scene = scene;
        this.workPane = workPane;

        this.webPagesMap = new ConcurrentHashMap<String, WebPage>();
        this.globalTestsResult = new LinkedHashMap<PatternEnum, TestResult>();

        loadTestResults();

        this.lastIndexReceivedFromPublicUrl = new AtomicInteger(0);
        this.lastIndexReceivedFromPrivateUrl = new AtomicInteger(0);

        createTestRun();

        copyToClipboard();
    }

    private void copyToClipboard() {
        scene.getAccelerators()
                .put(new KeyCodeCombination(KeyCode.C, KeyCombination.CONTROL_DOWN), new Runnable() {
                    @Override
                    public void run() {
                        final Clipboard clipboard = Clipboard.getSystemClipboard();
                        final ClipboardContent content = new ClipboardContent();
                        content.putString(selectedURL);
                        clipboard.setContent(content);
                    }
                });
    }

    private void loadTestResults() {
        for (PatternEnum pattern : PatternEnum.VALUES) {
            globalTestsResult.put(pattern, new TestResult("", pattern, TestResultEnum.NOT_TESTED));
        }
    }

    public void clear() {
        this.lastIndexReceivedFromPublicUrl.set(0);
        this.lastIndexReceivedFromPrivateUrl.set(0);

        webPagesMap.clear();
        headerInfo.clear();
        pageSource.clear();
        browserStyled.getEngine().loadContent("");
        browserText.getEngine().loadContent("");

        publicTableData.clear();
        privateTableData.clear();
        testResultsTableData.clear();
        headersTableData.clear();

        globalTestsResult.clear();
        loadTestResults();
    }

    private void createTestRun() {
        scrollTestRun = GuiUtils.getScrollPane(ScrollBarPolicy.ALWAYS, ScrollBarPolicy.ALWAYS, workPane.getMinWidth() - GuiTestsConfiguration.WIDTH, workPane.getMinHeight() - 20);

        testRun = new GridPane();
        testRun.setHgap(10);
        testRun.setPadding(new Insets(10, 10, 10, 10));
        testRun.setMinSize(workPane.getMinWidth() - GuiTestsConfiguration.WIDTH - 15, workPane.getMinHeight());
        testRun.setMaxWidth(workPane.getMinWidth() - GuiTestsConfiguration.WIDTH - 15);
        testRun.setId("rightPane");
//		testRun.gridLinesVisibleProperty().setValue(true);

        scrollTestRun.setContent(testRun);

        StackPane stack = new StackPane();
        stack.setMaxWidth(440);
        stack.setAlignment(Pos.TOP_RIGHT);

        TabPane tabPane = new TabPane();
        tabPane.setPadding(new Insets(0, 0, 0, 0));
        tabPane.setTabClosingPolicy(TabClosingPolicy.UNAVAILABLE);

        Tab tabPublic = createTab("Public URLs", "", 430, 263);
        Tab tabPrivate = createTab("Private URLs", "", 430, 263);

        VBox publicBox = createTabVBoxContent(430, 263, true, true);
        VBox privateBox = createTabVBoxContent(430, 263, true, true);

        tabPublic.setContent(publicBox);
        tabPrivate.setContent(privateBox);

        publicTableData = FXCollections.observableArrayList();
        privateTableData = FXCollections.observableArrayList();

        TableView<UrlInfo> infoTablePublic = createUrlInfoTable(publicTableData, publicBox, true);
        TableView<UrlInfo> infoTablePrivate = createUrlInfoTable(privateTableData, privateBox, true);

        tabPane.getTabs().addAll(tabPublic, tabPrivate);
        stack.getChildren().addAll(tabPane);

        tabPane.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<Tab>() {

            @Override
            public void changed(ObservableValue<? extends Tab> observable, Tab oldValue, Tab newValue) {
                if (newValue != null) {
                    clearTables();

                    VBox box = (VBox) newValue.getContent();
                    if (box.getChildren() instanceof ObservableList) {
                        TableView<UrlInfo> table = null;

                        if ("Public URLs".equals(newValue.getText())) {
                            table = infoTablePublic;
                        }
                        if ("Private URLs".equals(newValue.getText())) {
                            table = infoTablePrivate;
                        }

                        if (table != null) {
                            UrlInfo info = table.getSelectionModel().getSelectedItem();
                            if (info != null) {
                                selectedURL = info.getUrl();

                                updateTables(selectedURL);
                            }
                        }
                    }
                }
            }
        });

        HBox copyInfo = createInfoBox("/images/info.png", "Ctrl+C - copy selected URL to clipboard", 25, Pos.TOP_LEFT);

        HBox resultsBox = new HBox(20);
        resultsBox.setMinSize(300, 28);
        resultsBox.setMaxSize(300, 28);
        resultsBox.setPadding(new Insets(0, 0, 0, 10));
        HBox titleBoxTR = createTitleHBox(120, 28, "Test Results", Pos.TOP_CENTER, new Insets(10, 0, 0, 0));
        btViewGlobalResult = new Button();
        btViewGlobalResult.setMinWidth(120);
        btViewGlobalResult.setMaxWidth(120);
        btViewGlobalResult.setText("View Global Result");
        btViewGlobalResult.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent arg0) {
                clearTables();

                if (!webPagesMap.isEmpty()) {
                    for (WebPage wp : webPagesMap.values()) {
                        for (PatternEnum pattern : wp.getTestResults().keySet()) {
                            if (TestResultEnum.NOT_TESTED_VALUE == globalTestsResult.get(pattern).getState().getValue()
                                    || TestResultEnum.VULNERABLE_VALUE == wp.getTestResults().get(pattern).getState().getValue()) {
                                globalTestsResult.get(pattern).setState(wp.getTestResults().get(pattern).getState());
                                if (globalTestsResult.get(pattern).getVulnerabilities() == null) {
                                    globalTestsResult.get(pattern).setVulnerabilities(new ArrayList<Vulnerability>());
                                }
                                for (Vulnerability v : wp.getTestResults().get(pattern).getVulnerabilities()) {
                                    if (!globalTestsResult.get(pattern).getVulnerabilities().contains(v)) {
                                        globalTestsResult.get(pattern).getVulnerabilities().add(v);
                                    }
                                }
                            }
                        }
                    }
                }

                if (globalTestsResult != null) {
                    testResultsTableData.setAll(globalTestsResult.values());
                }
            }
        });

        resultsBox.getChildren().addAll(btViewGlobalResult, titleBoxTR);

        testResultsTableData = FXCollections.observableArrayList();
        TableView<TestResult> testResultsTable = createTestResultsTable(testResultsTableData, 300, 270);

        VBox vulnerabilityBox = new VBox();
        vulnerabilityBox.setMinSize(220, 270);
        vulnerabilityBox.setMaxSize(220, 270);
        vulnerabilitiesTableData = FXCollections.observableArrayList();
        TableView<Vulnerability> vulnerabilityTable = createVulnerabilityTable(vulnerabilitiesTableData, 220, 170);

        vulnerabilityInfo = new TextArea();
        vulnerabilityInfo.setMinSize(220, 100);
        vulnerabilityInfo.setMaxSize(220, 100);

        vulnerabilityBox.getChildren().addAll(vulnerabilityTable, vulnerabilityInfo);

        headersTableData = FXCollections.observableArrayList();
        TableView<HeaderKey> headersTable = createHeadersTable(headersTableData, 290, 235);
        headerInfo = new TextArea();
        headerInfo.setMinSize(290, 80);
        headerInfo.setMaxSize(290, 80);

        HBox webPageTitle = createTitleHBox(680, 29, "Webpage", Pos.TOP_CENTER, new Insets(10, 0, 0, 0));
        webPageTitle.setSpacing(20);
        group = new ToggleGroup();
        RadioButton btSource = new RadioButton("View Source");
        btSource.setToggleGroup(group);
        btSource.setSelected(true);
        RadioButton btViewStyledPage = new RadioButton("View Page Styled");
        btViewStyledPage.setToggleGroup(group);
        RadioButton btViewTextPage = new RadioButton("View Page Text");
        btViewTextPage.setToggleGroup(group);
        webPageTitle.getChildren().addAll(btSource, btViewStyledPage, btViewTextPage);
        group.selectedToggleProperty().addListener(new ChangeListener<Toggle>() {

            @Override
            public void changed(ObservableValue<? extends Toggle> observable, Toggle oldValue, Toggle newValue) {
                if (group.getSelectedToggle() != null) {
                    if (group.getSelectedToggle().equals(group.getToggles().get(0))) {
                        if (pageSource != null) {
                            if (browserStyled != null) {
                                browserStyled.setVisible(false);
                            }
                            if (browserText != null) {
                                browserText.setVisible(false);
                            }

                            pageSource.setVisible(true);
                        }
                    } else if (group.getSelectedToggle().equals(group.getToggles().get(1))) {
                        if (browserStyled != null && webEngineStyled != null) {
                            if (pageSource != null) {
                                pageSource.setVisible(false);
                            }
                            if (browserText != null) {
                                browserText.setVisible(false);
                            }

                            browserStyled.setVisible(true);
                        }
                    } else if (group.getSelectedToggle().equals(group.getToggles().get(2))) {
                        if (browserText != null && webEngineText != null) {
                            if (pageSource != null) {
                                pageSource.setVisible(false);
                            }
                            if (browserStyled != null) {
                                browserStyled.setVisible(false);
                            }

                            browserText.setVisible(true);
                        }
                    }
                }
            }
        });

        StackPane webPageStackPane = new StackPane();
        webPageStackPane.setMinSize(680, 316);
        webPageStackPane.setMaxSize(680, 316);
        webPageStackPane.setStyle("-fx-border-width: 1 1 1 1; -fx-border-color: rgb(175,175,175)");
        pageSource = new TextArea();
        pageSource.setMinSize(680, 316);

        browserStyled = createBrowser();
        webEngineStyled = browserStyled.getEngine();
        browserText = createBrowser();
        webEngineText = browserText.getEngine();
        webPageStackPane.getChildren().addAll(pageSource, browserStyled, browserText);

        testRun.add(stack, 0, 0, 45, 3);
        testRun.add(resultsBox, 45, 0, 46, 1);
        testRun.add(testResultsTable, 45, 1, 46, 1);
        testRun.add(vulnerabilityBox, 76, 1, 22, 1);
        testRun.add(copyInfo, 0, 4, 2, 1);
        testRun.add(headersTable, 0, 5, 28, 1);
        testRun.add(headerInfo, 0, 6, 28, 1);
        testRun.add(webPageTitle, 30, 4, 71, 1);
        testRun.add(webPageStackPane, 30, 5, 71, 2);
    }

    private HBox createInfoBox(String image, String message, double size, Pos position) {
        HBox infoBox = new HBox(5);
        infoBox.setAlignment(position);
        infoBox.setMinWidth(size);
        infoBox.setMaxWidth(size);
        javafx.scene.image.ImageView img = new javafx.scene.image.ImageView(image);
        infoBox.getChildren().add(img);

        Tooltip tooltip = new Tooltip(message);
        tooltip.setAutoHide(true);
        tooltip.setConsumeAutoHidingEvents(true);
        tooltip.setStyle("-fx-font-weight: bold");

        infoBox.setOnMouseEntered(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                Bounds b = img.localToScreen(img.getBoundsInLocal());
                tooltip.show(img, b.getMinX() - message.length() * 2.2, b.getMaxY() + 10);
            }
        });

        infoBox.setOnMouseExited(new EventHandler<Event>() {

            @Override
            public void handle(Event event) {
                tooltip.hide();
            }
        });

        return infoBox;
    }

    private WebView createBrowser() {
        WebView browser = new WebView();
        browser.setMinSize(678, 314);
        browser.setMaxSize(678, 314);
        browser.setVisible(false);

        return browser;
    }

    @SuppressWarnings("unchecked")
    private TableView<Vulnerability> createVulnerabilityTable(ObservableList<Vulnerability> tableData, double width, double height) {
        TableView<Vulnerability> table = new TableView<Vulnerability>();
        table.setMinSize(width, height);
        table.setMaxSize(width, height);
        table.setItems(tableData);

        TableColumn<Vulnerability, String> name = new TableColumn<Vulnerability, String>("Vulnerability Name");
        name.setMinWidth(200);
        name.setMaxWidth(200);
        name.setSortable(true);
        name.setCellValueFactory(new PropertyValueFactory<Vulnerability, String>("name"));

        table.getColumns().addAll(name);

        table.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<Vulnerability>() {

            @Override
            public void changed(ObservableValue<? extends Vulnerability> observable, Vulnerability oldValue, Vulnerability newValue) {
                if (newValue != null) {
                    if (vulnerabilityInfo != null) {
                        vulnerabilityInfo.setText(newValue.getExplanation());
                    }
                }
            }
        });

        return table;
    }

    @SuppressWarnings("unchecked")
    private TableView<TestResult> createTestResultsTable(ObservableList<TestResult> tableData, double width, double height) {
        TableView<TestResult> table = new TableView<TestResult>();
        table.setMinSize(width, height);
        table.setMaxSize(width, height);
        table.setItems(tableData);

        TableColumn<TestResult, String> pattern = new TableColumn<TestResult, String>("Pattern");
        pattern.setMinWidth(205);
        pattern.setMaxWidth(205);
        pattern.setSortable(true);
        pattern.setCellValueFactory(new PropertyValueFactory<TestResult, String>("pattern"));

        TableColumn<TestResult, ImageView> state = new TableColumn<TestResult, ImageView>("State");
        state.setMinWidth(80);
        state.setMaxWidth(80);
        state.setSortable(true);
        state.setCellValueFactory(new PropertyValueFactory<TestResult, ImageView>("stateImage"));

        table.getColumns().addAll(pattern, state);

        table.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<TestResult>() {

            @Override
            public void changed(ObservableValue<? extends TestResult> observable, TestResult oldValue, TestResult newValue) {
                if (newValue != null) {
                    if (vulnerabilityInfo != null) {
                        vulnerabilityInfo.setText(null);
                    }

                    if (vulnerabilitiesTableData != null) {
                        vulnerabilitiesTableData.clear();
                        vulnerabilitiesTableData.setAll(newValue.getVulnerabilities());
                    }
                }
            }
        });

        return table;
    }

    @SuppressWarnings("unchecked")
    private TableView<HeaderKey> createHeadersTable(ObservableList<HeaderKey> tableData, double width, double height) {
        TableView<HeaderKey> table = new TableView<HeaderKey>();
        table.setMinSize(width, height);
        table.setMaxSize(width, height);
        table.setItems(tableData);

        TableColumn<HeaderKey, String> header = new TableColumn<HeaderKey, String>("Headers / Comments in source");
        header.setMinWidth(width - 15);
        header.setMaxWidth(width - 15);
        header.setSortable(true);
        header.setCellValueFactory(new PropertyValueFactory<HeaderKey, String>("header"));

        table.getColumns().addAll(header);
        table.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<HeaderKey>() {

            @Override
            public void changed(ObservableValue<? extends HeaderKey> observable, HeaderKey oldValue, HeaderKey newValue) {
                if (newValue != null) {
                    StringBuilder text = new StringBuilder("");
                    if ("Comments".equals(newValue.getHeader()) && webPagesMap.get(selectedURL).getComments() != null
                            && !webPagesMap.get(selectedURL).getComments().isEmpty()) {
                        for (String s : webPagesMap.get(selectedURL).getComments()) {
                            for (String sp : s.split(";")) {
                                text.append(sp);
                                text.append("\n");
                            }
                        }
                    } else if (webPagesMap.get(selectedURL) != null && webPagesMap.get(selectedURL).getHeaders() != null
                            && webPagesMap.get(selectedURL).getHeaders().get(newValue) != null) {
                        for (String s : webPagesMap.get(selectedURL).getHeaders().get(newValue)) {
                            for (String sp : s.split(";")) {
                                text.append(sp);
                                text.append("\n");
                            }
                        }
                    }
                    headerInfo.setText(text.toString());
                }
            }
        });

        return table;
    }

    @SuppressWarnings("unchecked")
    private TableView<UrlInfo> createUrlInfoTable(final ObservableList<UrlInfo> tableData, VBox content, boolean afterAccessed) {
        TableView<UrlInfo> table = new TableView<UrlInfo>();
        table.setMinSize(427, 258);
        table.setMaxSize(427, 258);
        table.setItems(tableData);
        content.getChildren().add(table);

        TableColumn<UrlInfo, String> url = new TableColumn<UrlInfo, String>("URL");
        url.setMinWidth(410);
        url.setMaxWidth(410);
        url.setSortable(true);
        url.setCellValueFactory(new PropertyValueFactory<UrlInfo, String>("url"));

        table.getColumns().addAll(url);

        table.getSelectionModel().selectedItemProperty().addListener(new ChangeListener<UrlInfo>() {

            @Override
            public void changed(ObservableValue<? extends UrlInfo> observable, UrlInfo oldValue, UrlInfo newValue) {
                if (newValue != null) {
                    clearTables();

                    selectedURL = newValue.getUrl();

                    updateTables(selectedURL);
                }
            }
        });

        return table;
    }

    private void clearTables() {
        if (testResultsTableData != null) {
            testResultsTableData.clear();
        }

        if (vulnerabilitiesTableData != null) {
            vulnerabilitiesTableData.clear();
        }

        if (vulnerabilityInfo != null) {
            vulnerabilityInfo.setText(null);
        }

        if (group != null) {
            group.selectToggle(group.getToggles().get(0));
        }
        if (pageSource != null) {
            pageSource.setVisible(true);
            pageSource.setText(null);
        }
        if (browserStyled != null) {
            browserStyled.setVisible(false);
            webEngineStyled.load(null);
        }
        if (browserText != null) {
            browserText.setVisible(false);
            webEngineText.load(null);
        }

        if (headersTableData != null) {
            headersTableData.clear();
        }
        if (headerInfo != null) {
            headerInfo.setText("");
        }
    }

    private void updateTables(String selectedURL) {
        if (testResultsTableData != null) {
            testResultsTableData.clear();
        }

        if (webPagesMap != null && webPagesMap.get(selectedURL) != null && testResultsTableData != null) {
            testResultsTableData.setAll(webPagesMap.get(selectedURL).getTestResults().values());
        }

        if (group != null) {
            group.selectToggle(group.getToggles().get(0));
        }
        if (pageSource != null) {
            pageSource.setVisible(true);
            if (webPagesMap != null && webPagesMap.get(selectedURL) != null) {
                pageSource.setText(webPagesMap.get(selectedURL).getPage());
            }

            if (browserStyled != null) {
                browserStyled.setVisible(false);
                webEngineStyled.load(selectedURL);
            }
            if (browserText != null) {
                browserText.setVisible(false);
                webEngineText.loadContent(pageSource.getText());
            }
        }

        if (headersTableData != null) {
            if (webPagesMap.get(selectedURL) != null && webPagesMap.get(selectedURL).getHeaders() != null) {
                headersTableData.setAll(webPagesMap.get(selectedURL).getHeaders().keySet());
                if (webPagesMap.get(selectedURL).getComments() != null && !webPagesMap.get(selectedURL).getComments().isEmpty()) {
                    headersTableData.add(webPagesMap.get(selectedURL).new HeaderKey("Comments"));
                }
            }
        }
        if (headerInfo != null) {
            headerInfo.setText("");
        }
    }

    private VBox createTabVBoxContent(double width, double height, boolean paddings, boolean styled) {
        VBox vBox = new VBox();
        vBox.setMinSize(width, height);
        if (paddings) {
            vBox.setPadding(new Insets(5, 5, 5, 5));
        }
        if (styled) {
            vBox.setStyle("-fx-border-width: 0 1 1 1; -fx-border-color: rgb(175,175,175); -fx-background-color: rgb(245,245,245)");
        }

        return vBox;
    }

    private HBox createTitleHBox(double width, double height, String titleText, Pos alignement, Insets insets) {
        HBox titleHbox = new HBox();
        titleHbox.setMinSize(width, height);
        titleHbox.setMaxSize(width, height);
        titleHbox.setAlignment(alignement);
        titleHbox.setPadding(insets);
        Text title = new Text(titleText);
        title.setStyle("-fx-font-weight: bold;");
        titleHbox.getChildren().add(title);

        return titleHbox;
    }

    private Tab createTab(String tabText, String tooltipText, double width, double height) {
        Tab tab = new Tab();
        tab.setId("leftPaneTabs");
        tab.setText(tabText);
        if (tooltipText != null && !"".equals(tooltipText)) {
            Tooltip tooltip = new Tooltip(tooltipText);
            tab.setTooltip(tooltip);
        }
        ScrollPane scrollPane = createScrollPane(width, height);
        tab.setContent(scrollPane);

        return tab;
    }

    private ScrollPane createScrollPane(double width, double height) {
        ScrollPane scrollPane = GuiUtils.getScrollPane(ScrollBarPolicy.AS_NEEDED, ScrollBarPolicy.AS_NEEDED, 0, 0);
        scrollPane.setId("tabBorder");
        scrollPane.setPadding(new Insets(5, 0, 5, 0));
        scrollPane.setMinSize(width, height);
        scrollPane.setMaxSize(width, height);

        return scrollPane;
    }

    public GridPane getTestRun() {
        return testRun;
    }

    public ScrollPane getScrollTestRun() {
        return scrollTestRun;
    }

    @Override
    public void update(Observable arg0, Object arg1) {
        if (arg0 instanceof TaskProcessor) {
            TaskProcessor tp = (TaskProcessor) arg0;

            if (tp != null) {
                try {
                    Platform.runLater(new Runnable() {
                        public void run() {

                            if (TAG.equals((String) arg1)) {

                                ConcurrentMap<String, WebPage> map = tp.getTestLauncher().getWebPages();

                                if (map != null) {
                                    List<UrlInfo> listPublic = new ArrayList<UrlInfo>(tp.getTestLauncher().getPublicUrlsTested());
                                    List<UrlInfo> listPrivate = new ArrayList<UrlInfo>(tp.getTestLauncher().getPrivateUrlsTested());

                                    List<UrlInfo> publicURLS = new ArrayList<UrlInfo>(listPublic.subList(lastIndexReceivedFromPublicUrl.get(), listPublic.size()));
                                    List<UrlInfo> privateURLS = new ArrayList<UrlInfo>(listPrivate.subList(lastIndexReceivedFromPrivateUrl.get(), listPrivate.size()));

                                    for (UrlInfo info : publicURLS) {
                                        if (!publicTableData.contains(info)) {
                                            publicTableData.add(info);
                                        }
                                    }

                                    for (UrlInfo info : privateURLS) {
                                        if (!privateTableData.contains(info)) {
                                            privateTableData.add(info);
                                        }
                                    }

                                    lastIndexReceivedFromPublicUrl.set(listPublic.size());
                                    lastIndexReceivedFromPrivateUrl.set(listPrivate.size());

                                    if (publicURLS != null && !publicURLS.isEmpty()) {
                                        for (UrlInfo info : publicURLS) {
                                            WebPage wp = map.get(info.getUrl());
                                            if (wp != null && webPagesMap.get(info.getUrl()) == null) {
                                                webPagesMap.putIfAbsent(info.getUrl(), wp);
                                            }
                                        }
                                    }

                                    if (privateURLS != null && !privateURLS.isEmpty()) {
                                        for (UrlInfo info : privateURLS) {
                                            WebPage wp = map.get(info.getUrl());
                                            if (wp != null && webPagesMap.get(info.getUrl()) == null) {
                                                webPagesMap.putIfAbsent(info.getUrl(), wp);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    });
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public Button getBtViewGlobalResult() {
        return btViewGlobalResult;
    }

    public ObservableList<UrlInfo> getPublicTableData() {
        return publicTableData;
    }

    public ObservableList<UrlInfo> getPrivateTableData() {
        return privateTableData;
    }

    public ConcurrentMap<String, WebPage> getWebPagesMap() {
        return webPagesMap;
    }
}
