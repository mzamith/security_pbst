package org.feup.ses.pbst.GUI;

import java.util.ArrayList;
import java.util.List;
import java.util.Observable;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.ScrollPane.ScrollBarPolicy;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TabPane.TabClosingPolicy;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import org.feup.ses.pbst.AccessCredential;
import org.feup.ses.pbst.Enums.AccessLevel;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.GUI.widgets.CheckBoxPBST;
import org.feup.ses.pbst.TestConfAndResult;

public class GuiTestsConfiguration extends Observable {

    public static final String TIMEOUT = "timeout";
    public static final int DEFAULT_TIMEOUT = 5;
    public static final int DEFAULT_DISCOVERING_STOP = 1000;
    public static final double WIDTH = 350;

    private Stage stage;
    private StackPane workPane;
    private BorderPane testConf;
    private TestConfAndResult pbstTest;

    private CheckBoxPBST allPatterns;
//	private CheckBoxPBST spoofing;
//	private CheckBoxPBST tampering;
//	private CheckBoxPBST repudiation;
//	private CheckBoxPBST informationDisclosure;
//	private CheckBoxPBST dos;
//	private CheckBoxPBST elevationOfPrivilege;
//	private CheckBoxPBST multiPurpose;

    private TextField loginPage;
    private TextField homePage;
    private TextField failPage;
    private TextField usernameText;
    private TextField passwordText;
    private ComboBox<AccessLevel> accessLevelComboBox;
    private Button btAddCredential;
    private Button btUpdateCredential;
    private GridPane confCredentials;
    private VBox vBoxCredentials;
    private StackPane glassPane;

    private List<AccessCredential> accessCredentials;
    private BorderPane selectedAccessCredentialBP;
    private AccessCredential selectedAccessCredential;

    private TextField timeout;
    private Integer connectionsTimeout;
    private TextField discoverStop;
    private Integer discoverStopValue;

    public GuiTestsConfiguration(final Stage stage, final StackPane workPane, TestConfAndResult pbstTest) {
        this.stage = stage;
        this.workPane = workPane;
        this.pbstTest = pbstTest;

        this.connectionsTimeout = DEFAULT_TIMEOUT;
        this.discoverStopValue = DEFAULT_DISCOVERING_STOP;

        createTestConf();
        createGlass();
    }

    private void createGlass() {
        glassPane = new StackPane();
        glassPane.setId("glassPane");
        glassPane.setPadding(new Insets(0, 0, 0, 0));
        glassPane.setMinSize(WIDTH, workPane.getMinHeight());
        glassPane.setMaxWidth(WIDTH);
        glassPane.setVisible(false);
    }

    private void createTestConf() {
        testConf = new BorderPane();
        testConf.setPadding(new Insets(10, 10, 10, 10));
        testConf.setMinSize(WIDTH, workPane.getMinHeight());
        testConf.setMaxWidth(WIDTH);
        testConf.setId("leftPane");

        GridPane topConf = new GridPane();
        topConf.setVgap(5);
        topConf.setHgap(5);

        Text loginPageLabel = new Text("Login Page");
        topConf.add(loginPageLabel, 0, 0);

        loginPage = new TextField();
        loginPage.setMinWidth(WIDTH - 87);
        loginPage.setMaxWidth(WIDTH - 87);
        loginPage.textProperty().addListener(new ChangeListener<String>() {

            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                pbstTest.setLoginPage(newValue);
            }
        });
        topConf.add(loginPage, 1, 0);

        Text homePageLabel = new Text("Home Page");
        topConf.add(homePageLabel, 0, 1);

        homePage = new TextField();
        homePage.setMinWidth(WIDTH - 87);
        homePage.setMaxWidth(WIDTH - 87);
        homePage.textProperty().addListener(new ChangeListener<String>() {

            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                pbstTest.setHomePage(newValue);
            }
        });
        topConf.add(homePage, 1, 1);

        Text loginFailLabel = new Text("Fail Page");
        topConf.add(loginFailLabel, 0, 2);

        failPage = new TextField();
        failPage.setMinWidth(WIDTH - 87);
        failPage.setMaxWidth(WIDTH - 87);
        failPage.textProperty().addListener(new ChangeListener<String>() {

            @Override
            public void changed(ObservableValue<? extends String> observable, String oldValue, String newValue) {
                pbstTest.setFailPage(newValue);
            }
        });
        topConf.add(failPage, 1, 2);

        TabPane tabPane = new TabPane();
        tabPane.setPadding(new Insets(10, 0, 0, 0));
        tabPane.setTabClosingPolicy(TabClosingPolicy.UNAVAILABLE);
        Tab tabLeft = new Tab();
        tabLeft.setId("leftPaneTabs");
        tabLeft.setText("Security Pattern Tests");
        ScrollPane spTL = GuiUtils.getScrollPane(ScrollBarPolicy.NEVER, ScrollBarPolicy.AS_NEEDED, 0, 0);
        spTL.setId("tabBorder");
        spTL.setPadding(new Insets(5, 0, 5, 0));
        spTL.setContent(getPatternsCheckBox(WIDTH - 60));
        tabLeft.setContent(spTL);

        Tab tabCenter = new Tab();
        tabCenter.setText("Access Credentials");
        tabCenter.setContent(getCredentials());

        Tab tabRight = new Tab();
        tabRight.setText("Testing options");
        tabRight.setContent(getTestingOptions());

        tabPane.getTabs().add(tabLeft);
        tabPane.getTabs().add(tabCenter);
        tabPane.getTabs().add(tabRight);

        testConf.setTop(topConf);
        testConf.setCenter(tabPane);
    }

    private GridPane getTestingOptions() {
        GridPane gp = new GridPane();
        gp.setId("tabBorder");
        gp.setMinWidth(329);
        gp.setMaxWidth(329);

        ScrollPane spCenter = GuiUtils.getScrollPane(ScrollBarPolicy.NEVER, ScrollBarPolicy.AS_NEEDED, WIDTH - 20, 0);
        spCenter.setId("scrollPaneBorderTransparent");
        spCenter.setPadding(new Insets(5, 10, 5, 10));
        spCenter.setMinWidth(327);
        spCenter.setMaxWidth(327);

        VBox boxContent = new VBox(20);
        boxContent.setMinWidth(300);
        boxContent.setMaxWidth(300);

        HBox timeoutBox = new HBox(5);
        timeoutBox.setPrefHeight(GUI.GUI_TOP_PANE_HEIGHT);
        timeoutBox.setAlignment(Pos.CENTER_LEFT);
        timeoutBox.setMinWidth(250);
        timeoutBox.setMaxWidth(250);
        Text timeoutLabel = new Text("Connections timeout");
        timeout = new TextField("" + connectionsTimeout);
        timeout.setMinWidth(30);
        timeout.setMaxWidth(30);
        timeout.lengthProperty().addListener(new ChangeListener<Number>() {

            @Override
            public void changed(ObservableValue<? extends Number> observable, Number oldValue, Number newValue) {
                if (timeout.getText().length() > 2) {
                    timeout.setText(timeout.getText().substring(0, 2));
                }
                try {
                    connectionsTimeout = Integer.parseInt(timeout.getText());
                } catch (NumberFormatException nfe) {
                    timeout.setText("");
                    connectionsTimeout = 0;
                }
                setChanged();
                notifyObservers(TIMEOUT);
            }
        });
        Text timeoutMeasure = new Text("Seconds");
        timeoutBox.getChildren().addAll(timeoutLabel, timeout, timeoutMeasure);

        HBox discoverStopBox = new HBox(5);
        discoverStopBox.setPrefHeight(GUI.GUI_TOP_PANE_HEIGHT);
        discoverStopBox.setAlignment(Pos.CENTER_LEFT);
        discoverStopBox.setMinWidth(250);
        discoverStopBox.setMaxWidth(250);
        discoverStop = new TextField("" + discoverStopValue);
        discoverStop.setMinWidth(50);
        discoverStop.setMaxWidth(50);
        discoverStop.lengthProperty().addListener(new ChangeListener<Number>() {

            @Override
            public void changed(ObservableValue<? extends Number> observable, Number oldValue, Number newValue) {
                if (discoverStop.getText().length() > 5) {
                    discoverStop.setText(discoverStop.getText().substring(0, 5));
                }
                try {
                    discoverStopValue = Integer.parseInt(discoverStop.getText());
                } catch (NumberFormatException nfe) {
                    discoverStop.setText("");
                    discoverStopValue = 0;
                }
                setChanged();
                notifyObservers(TIMEOUT);
            }
        });
        discoverStopBox.getChildren().addAll(new Text("Stop discovering after discover"), discoverStop, new Text("URLs"));

        boxContent.getChildren().add(timeoutBox);
        boxContent.getChildren().add(discoverStopBox);

        spCenter.setContent(boxContent);

        gp.add(spCenter, 0, 1);

        return gp;
    }

    private GridPane getCredentials() {
        GridPane gp = new GridPane();
        gp.setId("tabBorder");
        gp.setMinWidth(329);
        gp.setMaxWidth(329);

        ScrollPane spCenter = GuiUtils.getScrollPane(ScrollBarPolicy.NEVER, ScrollBarPolicy.AS_NEEDED, WIDTH - 20, 0);
        spCenter.setId("scrollPaneBorderTransparent");
        spCenter.setPadding(new Insets(5, 0, 5, 0));
        spCenter.setMinWidth(327);
        spCenter.setMaxWidth(327);

        vBoxCredentials = new VBox();
        vBoxCredentials.setId("vBoxCredentials");
        vBoxCredentials.setAlignment(Pos.TOP_LEFT);
        vBoxCredentials.getStylesheets().add(getClass().getClassLoader().getResource("application.css").toExternalForm());

        spCenter.setContent(vBoxCredentials);

        confCredentials = new GridPane();
        confCredentials.setId("confCredentials");
        confCredentials.setPadding(new Insets(5, 5, 5, 5));
        confCredentials.setVgap(5);
        confCredentials.setHgap(5);

        Text usernameLabel = new Text("Username");
        confCredentials.add(usernameLabel, 0, 0);

        usernameText = new TextField();
        usernameText.setMinWidth(180);
        usernameText.setMaxWidth(180);
        confCredentials.add(usernameText, 1, 0);

        Text passwordLabel = new Text("Password");
        confCredentials.add(passwordLabel, 0, 1);

        passwordText = new TextField();
        passwordText.setMinWidth(180);
        passwordText.setMaxWidth(180);
        confCredentials.add(passwordText, 1, 1);

        Text accessLevelLabel = new Text("Access Level");
        confCredentials.add(accessLevelLabel, 0, 2);

        accessLevelComboBox = new ComboBox<AccessLevel>();
        accessLevelComboBox.setMinWidth(180);
        accessLevelComboBox.setMaxWidth(180);
        accessLevelComboBox.getItems().addAll(AccessLevel.values());
        confCredentials.add(accessLevelComboBox, 1, 2);

        btAddCredential = new Button();
        btAddCredential.setMinWidth(60);
        btAddCredential.setMaxWidth(60);
        btAddCredential.setText("Add");
        btAddCredential.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent event) {
                if (usernameText.getStyleClass().contains("error")) {
                    usernameText.getStyleClass().remove("error");
                }
                if (passwordText.getStyleClass().contains("error")) {
                    passwordText.getStyleClass().remove("error");
                }
                if (accessLevelComboBox.getStyleClass().contains("error")) {
                    accessLevelComboBox.getStyleClass().remove("error");
                }

                if (!"".equals(usernameText.getText().trim()) && !"".equals(passwordText.getText().trim()) && accessLevelComboBox.getValue() != null) {
                    AccessCredential access = new AccessCredential(usernameText.getText(), passwordText.getText(), accessLevelComboBox.getValue());

                    if (accessCredentials == null) {
                        accessCredentials = new ArrayList<AccessCredential>();
                        pbstTest.setCredentials(accessCredentials);
                    }

                    if (!accessCredentials.contains(access)) {
                        accessCredentials.add(access);

                        addToListAccessCredentials(vBoxCredentials, access);
                    } else {
                        Tooltip tp = new Tooltip("Already exists an Access Credential with username " + usernameText.getText() + "!");
                        tp.setAutoHide(true);
                        tp.setStyle("-fx-background-color: red; -fx-font-weight: bold;");
                        tp.show(usernameText, stage.getX() + 250, stage.getY() + 150);
                    }
                } else {
                    if ("".equals(usernameText.getText().trim())) {
                        usernameText.getStyleClass().add("error");
                    }

                    if ("".equals(passwordText.getText().trim())) {
                        passwordText.getStyleClass().add("error");
                    }

                    if (accessLevelComboBox.getValue() == null) {
                        accessLevelComboBox.getStyleClass().add("error");
                    }
                }
            }
        });
        confCredentials.add(btAddCredential, 2, 2);

        btUpdateCredential = new Button();
        btUpdateCredential.setMinWidth(60);
        btUpdateCredential.setMaxWidth(60);
        btUpdateCredential.setText("Update");
        btUpdateCredential.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent event) {

                selectedAccessCredential.setUsername(usernameText.getText());
                selectedAccessCredential.setPassword(passwordText.getText());
                selectedAccessCredential.setAccessLevel(accessLevelComboBox.getValue());

                updateListAccessCredentials(selectedAccessCredentialBP, selectedAccessCredential);

                for (Node node : confCredentials.getChildren()) {
                    if (node instanceof Button && ((Button) node).getText().equals("Update")) {
                        confCredentials.getChildren().remove(node);
                        confCredentials.add(btAddCredential, 2, 2);
                        break;
                    }
                }
            }
        });

        gp.add(confCredentials, 0, 0);
        gp.add(spCenter, 0, 1);

        return gp;
    }

    private void updateListAccessCredentials(final BorderPane bp, AccessCredential accessCredential) {
        for (Node node : bp.getChildren()) {
            if (node instanceof GridPane && ((GridPane) node).getId().equals("left")) {
                for (Node node2 : ((GridPane) node).getChildren()) {
                    if (node2 instanceof Text && "username".equals(((Text) node2).getId())) {
                        ((Text) node2).setText(accessCredential.getUsername());
                    }
                    if (node2 instanceof Text && "password".equals(((Text) node2).getId())) {
                        ((Text) node2).setText(accessCredential.getPassword());
                    }
                    if (node2 instanceof Text && "accessLevel".equals(((Text) node2).getId())) {
                        ((Text) node2).setText(accessCredential.getAccessLevel().getLiteral());
                    }
                }

                break;
            }
        }
    }

    public void addToListAccessCredentials(final VBox parent, final AccessCredential access) {
        BorderPane bp = new BorderPane();
        GridPane gridPaneLeft = new GridPane();
        gridPaneLeft.setId("left");
        gridPaneLeft.setPadding(new Insets(5, 5, 5, 5));
        gridPaneLeft.setMinWidth(WIDTH - 70);
        gridPaneLeft.setMaxWidth(WIDTH - 70);
        gridPaneLeft.setVgap(5);
        gridPaneLeft.setHgap(5);

        GridPane gridPaneRight = new GridPane();
        gridPaneRight.setPadding(new Insets(5, 5, 5, 5));
        gridPaneRight.setVgap(5);
        gridPaneRight.setHgap(5);

        bp.setLeft(gridPaneLeft);
        bp.setCenter(gridPaneRight);

        Text usernameLabel = new Text("Username");
        usernameLabel.getStyleClass().add("bold");
        gridPaneLeft.add(usernameLabel, 0, 0);
        Text username = new Text(access.getUsername().substring(0, Math.min(access.getUsername().length(), 40)));
        username.setId("username");
        gridPaneLeft.add(username, 1, 0);

        Text passwordLabel = new Text("Password");
        passwordLabel.getStyleClass().add("bold");
        gridPaneLeft.add(passwordLabel, 0, 1);
        Text password = new Text(access.getPassword().substring(0, Math.min(access.getPassword().length(), 40)));
        password.setId("password");
        gridPaneLeft.add(password, 1, 1);

        Text accessLevelLabel = new Text("Access Level");
        accessLevelLabel.getStyleClass().add("bold");
        gridPaneLeft.add(accessLevelLabel, 0, 2);
        Text accessLevel = new Text(access.getAccessLevel().getLiteral());
        accessLevel.setId("accessLevel");
        gridPaneLeft.add(accessLevel, 1, 2);

        GridPane update = GuiUtils.getMenuButton(null, new Image("images/update.png"), 25, 25, 1, "image-button");
        update.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                usernameText.setText(access.getUsername());
                passwordText.setText(access.getPassword());
                accessLevelComboBox.setValue(access.getAccessLevel());

                selectedAccessCredentialBP = bp;
                selectedAccessCredential = access;

                for (Node node : confCredentials.getChildren()) {
                    if (node instanceof Button && ((Button) node).getText().equals("Add")) {
                        confCredentials.getChildren().remove(node);
                        confCredentials.add(btUpdateCredential, 2, 2);
                        break;
                    }
                }
            }
        });
        gridPaneRight.add(update, 0, 0);

        GridPane delete = GuiUtils.getMenuButton(null, new Image("images/delete.png"), 25, 25, 1, "image-button");
        delete.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                accessCredentials.remove(access);
                for (Node node : parent.getChildren()) {
                    if (node == bp) {
                        parent.getChildren().remove(node);
                        break;
                    }
                }
            }
        });
        gridPaneRight.add(delete, 0, 1);

        parent.getChildren().add(bp);
    }

    private VBox getPatternsCheckBox(double width) {
        VBox vBox = new VBox();
        vBox.setMinWidth(width);
        vBox.setAlignment(Pos.TOP_LEFT);
        vBox.getStylesheets().add(getClass().getClassLoader().getResource("application.css").toExternalForm());
        vBox.setId("tabLeftContent");

        allPatterns = new CheckBoxPBST(vBox, "Select All Security Pattern Tests", true, false);

        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_AL.getLiteral(), allPatterns, false));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_AS.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_AB.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.REPUDIATION_AI.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_AE.getLiteral(), allPatterns, false));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_AE.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_BR.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_BA.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_C.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_CS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_CJ.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_CDS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_CMS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_CDP.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_CLP.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.ELEVATION_OF_PRIVILEGE_C.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.ELEVATION_OF_PRIVILEGE_COF.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.ELEVATION_OF_PRIVILEGE_CPC.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.ELEVATION_OF_PRIVILEGE_CVAS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_CT.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_CT.getLiteral(), allPatterns, true));

        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_DZ.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_DS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.ELEVATION_OF_PRIVILEGE_DR.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_DSM.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_EDC.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_ES.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_EXS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.ELEVATION_OF_PRIVILEGE_ED.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_FD.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_FAWE.getLiteral(), allPatterns, true));

        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_IO.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_IRP.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_IV.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_IWA.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_LE.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_LA.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_LP.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_MI.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_MIG.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_MRD.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_MR.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_MS.getLiteral(), allPatterns, true));

        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_NAB.getLiteral(), allPatterns, true));

        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_OTO.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_OT.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_PFF.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_PS.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_PD.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_PEP.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_PRP.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_PBF.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_PI.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_RE.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_RW.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_RM.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_RS.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_RBAC.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_SDS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.DOS_S.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_SCOM.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.REPUDIATION_SL.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_SMR.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_SSF.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_SSP.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_SSO.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.ELEVATION_OF_PRIVILEGE_SRP.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_SA.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_SC.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_SS.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_SS.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_SAP.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_SSO.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.SPOOFING_SSOD.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_STF.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.DOS_SP.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_S.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_SF.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.INFORMATION_DISCLOSURE_SD.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_TS.getLiteral(), allPatterns, true));
//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_TP.getLiteral(), allPatterns, true));
        allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.MULTI_PURPOSE_TP.getLiteral(), allPatterns, true));

//    	allPatterns.addChild(new CheckBoxPBST(vBox, PatternEnum.TAMPERING_ULFEWR.getLiteral(), allPatterns, true));
        //Test category - Spoofing-------------------------------------------------------
        {
//	    	spoofing = new CheckBoxPBST(vBox, Spoofing.class, true, allPatterns);
//	    	allPatterns.addChild(spoofing);
        }

        //Test category - Tampering-------------------------------------------------------
        {
//	    	tampering = new CheckBoxPBST(vBox, Tampering.class, true, allPatterns);
//	    	allPatterns.addChild(tampering);
        }

        //Test category - Repudiation-------------------------------------------------------
        {
//	    	repudiation = new CheckBoxPBST(vBox, Repudiation.class, true, allPatterns);
//	    	allPatterns.addChild(repudiation);
        }

        //Test category - Information Disclosure-------------------------------------------------------
        {
//	    	informationDisclosure = new CheckBoxPBST(vBox, InformationDisclosure.class, true, allPatterns);
//	    	allPatterns.addChild(informationDisclosure);
        }

        //Test category - DoS-------------------------------------------------------
        {
//	    	dos = new CheckBoxPBST(vBox, DOS.class, true, allPatterns);
//	    	allPatterns.addChild(dos);
        }

        //Test category - Elevation Of Privileges-------------------------------------------------------
        {
//	    	elevationOfPrivilege = new CheckBoxPBST(vBox, ElevationOfPrivilege.class, true, allPatterns);
//	    	allPatterns.addChild(elevationOfPrivilege);
        }

        //Test category - Multi Purpose-------------------------------------------------------
        {
//	    	multiPurpose = new CheckBoxPBST(vBox, MultiPurpose.class, true, allPatterns);
//	    	allPatterns.addChild(multiPurpose);
        }

        pbstTest.setPatterns(allPatterns);
        pbstTest.setGuiPatterns(allPatterns);

        return vBox;
    }

    public BorderPane getTestConf() {
        return testConf;
    }

    public StackPane getGlassPane() {
        return glassPane;
    }

    public TestConfAndResult getPbstTest() {
        return pbstTest;
    }

    public void setPbstTest(TestConfAndResult pbstTest) {
        this.pbstTest = pbstTest;
    }

    public CheckBoxPBST getAllPatterns() {
        return allPatterns;
    }

    public void setAllPatterns(CheckBoxPBST allPatterns) {
        this.allPatterns = allPatterns;
    }

    public TextField getLoginPage() {
        return loginPage;
    }

    public void setLoginPage(TextField loginPage) {
        this.loginPage = loginPage;
    }

    public TextField getHomePage() {
        return homePage;
    }

    public void setHomePage(TextField homePage) {
        this.homePage = homePage;
    }

    public TextField getFailPage() {
        return failPage;
    }

    public void setFailPage(TextField failPage) {
        this.failPage = failPage;
    }

    public List<AccessCredential> getAccessCredentials() {
        return accessCredentials;
    }

    public void setAccessCredentials(List<AccessCredential> accessCredentials) {
        this.accessCredentials = accessCredentials;
    }

    public VBox getvBoxCredentials() {
        return vBoxCredentials;
    }

    public TextField getUsernameText() {
        return usernameText;
    }

    public TextField getPasswordText() {
        return passwordText;
    }

    public ComboBox<AccessLevel> getAccessLevelComboBox() {
        return accessLevelComboBox;
    }

    public Integer getConnectionsTimeout() {
        return connectionsTimeout;
    }

    public Integer getDiscoverStopValue() {
        return discoverStopValue;
    }

}
