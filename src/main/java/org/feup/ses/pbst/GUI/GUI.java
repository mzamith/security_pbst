package org.feup.ses.pbst.GUI;

import java.awt.Desktop;
import java.io.IOException;
import java.util.Observable;
import java.util.Observer;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.geometry.Rectangle2D;
import javafx.scene.Scene;
import javafx.scene.image.Image;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.stage.WindowEvent;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.reports.Report;

public class GUI extends Observable implements Observer {

    public static final double GUI_TOP_PANE_HEIGHT = 30;
    public static final String TAG = "gui";
    public static final String UPDATE = "update";
    public static final String STOP_DISCOVER_STAGE = "stopDiscoverStage";
    public static final String STOP_TEST_STAGE = "stopTestStage";

    private long startTime = 0;
    private long endTime = 0;

    private final double stageWidth;
    private final double stageHeight;

    private final GuiMenu guiMenu;
    private final GuiTopBar guiTopBar;
    private GuiTestsConfiguration guiTestsConfiguration;
    private GuiTestsRun guiTestsRun;
//    private GuiTester guiTester;

    private Integer connectionsTimeout = 5;
    private Integer discoverinStopValue = GuiTestsConfiguration.DEFAULT_DISCOVERING_STOP;
    ;

    private TestConfAndResult pbstTest;
    private TaskProcessor taskProcessor;

    private final Stage stage;
    private Scene scene;
    private final Rectangle2D primaryScreenBounds;

    private StackPane workPane;

    public GUI(final Stage stage) {
        this.stage = stage;

        primaryScreenBounds = Screen.getPrimary().getVisualBounds();
        stageWidth = primaryScreenBounds.getWidth();
        stageHeight = primaryScreenBounds.getHeight();

        stage.setX(primaryScreenBounds.getMinX());
        stage.setY(primaryScreenBounds.getMinY());
        stage.setWidth(stageWidth);
        stage.setHeight(stageHeight);
        stage.setResizable(true);
        Image image = new Image(getClass().getClassLoader().getResourceAsStream("images/PBST_logo.png"));
        stage.getIcons().add(image);

        BorderPane root = new BorderPane();

        scene = new Scene(root, stageWidth, stageHeight);
        scene.getStylesheets().add(getClass().getClassLoader().getResource("application.css").toExternalForm());

        pbstTest = new TestConfAndResult();

        guiMenu = new GuiMenu(stage, pbstTest);
        guiMenu.addObserver(this);

        guiTopBar = new GuiTopBar(primaryScreenBounds);
        guiTopBar.addObserver(this);
        this.addObserver(guiTopBar);

        AnchorPane topPane = getTopPane();
        root.setTop(topPane);
        HBox menuBox = guiMenu.getMenuBox();
        topPane.getChildren().add(menuBox);
        AnchorPane.setLeftAnchor(menuBox, 0.0);

        HBox topBarBox = guiTopBar.getBarBox();
        guiMenu.addCloseMenuAction(topBarBox);
        topPane.getChildren().add(topBarBox);
        AnchorPane.setLeftAnchor(topBarBox, 120.0);

        StackPane workPane = getWorkPane();
        root.setLeft(workPane);

        stage.setOnCloseRequest((WindowEvent event) -> {
            if (taskProcessor != null) {
                taskProcessor.stop();
            }
        });
    }

    private AnchorPane getTopPane() {
        AnchorPane topPane = new AnchorPane();
        topPane.setPadding(new Insets(0, 10, 0, 10));
        topPane.setId("topPane");

        return topPane;
    }

    private StackPane getWorkPane() {
        workPane = new StackPane();
        workPane.setPadding(new Insets(0, 0, 0, 0));
        workPane.setMinWidth(stageWidth);
        workPane.setAlignment(Pos.TOP_LEFT);

        workPane.getChildren().addAll(getSecurityTestContent(),
                guiTestsConfiguration.getGlassPane(),
                guiMenu.getMenuPane());//,
//        		                      guiTester.getBrowserPane());

        guiMenu.addCloseMenuAction(guiTestsConfiguration.getGlassPane());

        return workPane;
    }

    private BorderPane getSecurityTestContent() {
        if (guiTestsConfiguration == null) {
            guiTestsConfiguration = new GuiTestsConfiguration(stage, workPane, pbstTest);
            guiTestsConfiguration.addObserver(this);
        }

        if (guiTestsRun == null) {
            guiTestsRun = new GuiTestsRun(scene, workPane);
        }

//    	if(guiTester == null){
//    		guiTester = new GuiTester(stage);
//    	}
        BorderPane content = new BorderPane();
        content.setLeft(guiTestsConfiguration.getTestConf());
        content.setCenter(guiTestsRun.getScrollTestRun());

        return content;
    }

    public Scene getScene() {
        return scene;
    }

    public void setScene(Scene scene) {
        this.scene = scene;
    }

    public Integer getConnectionsTimeout() {
        return connectionsTimeout;
    }

    public Integer getDiscoverinStopValue() {
        return discoverinStopValue;
    }

    @Override
    public void update(Observable arg0, Object arg1) {
        if (GuiTopBar.TIMEOUT.equals((String) arg1) && arg0 instanceof GuiTestsConfiguration) {
            connectionsTimeout = guiTestsConfiguration.getConnectionsTimeout();
            discoverinStopValue = guiTestsConfiguration.getDiscoverStopValue();
            setChanged();
            notifyObservers(GuiTopBar.TIMEOUT);
        }
        if (GuiMenu.SHOW.equals((String) arg1)) {
            guiTestsConfiguration.getGlassPane().setVisible(true);
        } else if (GuiMenu.HIDE.equals((String) arg1) && (taskProcessor == null || taskProcessor.isFinished())) {
            guiTestsConfiguration.getGlassPane().setVisible(false);
        } else if (GuiMenu.NEW.equals((String) arg1)) {
            guiTestsConfiguration.getLoginPage().setText("");
            guiTestsConfiguration.getHomePage().setText("");
            guiTestsConfiguration.getFailPage().setText("");

//			for(CheckBoxPBST test: guiTestsConfiguration.getAllPatterns().getChilds()){
//				for(CheckBoxPBST child: test.getChilds()){
//					child.getButton().setSelected(false);
//					child.updateGroup(child.getGroup());
//				}
//			}
            pbstTest = new TestConfAndResult();
            guiMenu.setPbstTest(pbstTest);
            guiTestsConfiguration.setPbstTest(pbstTest);

            guiTestsConfiguration.getAllPatterns().getChilds().stream().map((child) -> {
                child.getButton().setSelected(false);
                return child;
            }).forEachOrdered((child) -> {
                child.updateGroup(child.getGroup());
            });

            pbstTest.setPatterns(guiTestsConfiguration.getAllPatterns());
            guiMenu.getPbstTest().setGuiPatterns(guiTestsConfiguration.getAllPatterns());
            guiTestsConfiguration.getPbstTest().setGuiPatterns(guiTestsConfiguration.getAllPatterns());

            guiTestsConfiguration.getUsernameText().setText("");
            guiTestsConfiguration.getPasswordText().setText("");
            guiTestsConfiguration.getAccessLevelComboBox().setValue(null);
            guiTestsConfiguration.getvBoxCredentials().getChildren().removeAll(guiTestsConfiguration.getvBoxCredentials().getChildren());

            guiTopBar.clearToNew();
            guiTestsRun.clear();

            guiTestsConfiguration.getGlassPane().setVisible(false);
        } else if (GuiMenu.OPEN.equals((String) arg1)) {
            pbstTest = guiMenu.getPbstTest();
            guiTestsConfiguration.setPbstTest(pbstTest);

            guiTestsConfiguration.getLoginPage().setText(pbstTest.getLoginPage());
            guiTestsConfiguration.getHomePage().setText(pbstTest.getHomePage());
            guiTestsConfiguration.getFailPage().setText(pbstTest.getFailPage());

//			for(CheckBoxPBST test: guiTestsConfiguration.getAllPatterns().getChilds()){
//				for(CheckBoxPBST child: test.getChilds()){
//					child.getButton().setSelected(guiMenu.getPbstTest().getPatterns().get(child.getName()) != null ? guiMenu.getPbstTest().getPatterns().get(child.getName()).booleanValue() : false);
//					child.updateGroup(child.getGroup());
//				}
//			}
            guiTestsConfiguration.getAllPatterns().getChilds().stream().map((child) -> {
                child.getButton().setSelected(pbstTest.getPatterns().get(child.getName()) != null ? pbstTest.getPatterns().get(child.getName()) : false);
                return child;
            }).forEachOrdered((child) -> {
                child.updateGroup(child.getGroup());
            });

            guiTestsConfiguration.getvBoxCredentials().getChildren().clear();
            guiTestsConfiguration.getUsernameText().setText("");
            guiTestsConfiguration.getPasswordText().setText("");
            guiTestsConfiguration.getAccessLevelComboBox().getSelectionModel().select(-1);
            guiTestsConfiguration.setAccessCredentials(pbstTest.getCredentials());
            if (guiTestsConfiguration.getAccessCredentials() != null) {
                guiTestsConfiguration.getAccessCredentials().forEach((ac) -> {
                    guiTestsConfiguration.addToListAccessCredentials(guiTestsConfiguration.getvBoxCredentials(), ac);
                });
            }

            guiTopBar.clear();
            guiTestsRun.clear();

            guiTopBar.getDiscoveredCount().setText("" + pbstTest.getTotalDiscovered());
            guiTopBar.getToBeTestedCount().setText("" + pbstTest.getTotalSelectedToBeTested());
            guiTopBar.getPublicCount().setText("" + pbstTest.getTotalPublic());
            guiTopBar.getPrivateCount().setText("" + pbstTest.getTotalPrivate());
            guiTopBar.getNotAccessibleCount().setText("" + pbstTest.getTotalNotAccessible());
            guiTopBar.getTestedPublicCount().setText("" + pbstTest.getTotalPublicTested());
            guiTopBar.getTestedPrivateCount().setText("" + pbstTest.getTotalPrivateTested());

            if (pbstTest.getTotalDiscovered() != null && pbstTest.getTotalDiscovered() > 0) {

                int totalProcessed = pbstTest.getTotalPublic() + pbstTest.getTotalPrivate() + pbstTest.getTotalNotAccessible();
                double discovered = (double) totalProcessed / (double) pbstTest.getTotalDiscovered();

                guiTopBar.getProgressBarDiscover().setProgress(discovered);
                guiTopBar.getPercentageDiscover().setText("" + (Math.round(discovered * 100)) + "%");

                int tested = pbstTest.getTotalPublicTested() + pbstTest.getTotalPrivateTested();
                if (tested > 0 && pbstTest.getWebPages() != null && pbstTest.getWebPages().size() > 0) {
                    double testedPercent = (double) tested / (double) (pbstTest.getWebPages().size());
                    guiTopBar.getProgressBarTested().progressProperty().set(testedPercent);
                    guiTopBar.getPercentageTested().setText("" + (Math.round(testedPercent * 100)) + "%");
                }
            }

            if (pbstTest.getWebPages() != null) {
                guiTestsRun.getWebPagesMap().putAll(pbstTest.getWebPages());
                guiTestsRun.getPublicTableData().addAll(pbstTest.getPublicUrlsTested());
                guiTestsRun.getPrivateTableData().addAll(pbstTest.getPrivateUrlsTested());
            }

            guiTestsConfiguration.getGlassPane().setVisible(false);

        } else if (GuiMenu.RUN.equals((String) arg1)) {
            startTime = System.currentTimeMillis();
            endTime = 0;

            if (connectionsTimeout == null || connectionsTimeout == 0) {
                connectionsTimeout = GuiTestsConfiguration.DEFAULT_TIMEOUT;
                setChanged();
                notifyObservers(GuiTopBar.TIMEOUT);
            }

            if (discoverinStopValue == null || discoverinStopValue == 0) {
                discoverinStopValue = GuiTestsConfiguration.DEFAULT_DISCOVERING_STOP;
                setChanged();
                notifyObservers(GuiTopBar.TIMEOUT);
            }

            taskProcessor = new TaskProcessor(connectionsTimeout, discoverinStopValue, pbstTest);
            taskProcessor.addObserver(guiTopBar);
            taskProcessor.addObserver(guiTestsRun);
            taskProcessor.addObserver(this);
            if (taskProcessor.start()) {
                guiTestsConfiguration.getGlassPane().setVisible(true);
                guiTopBar.clear();
                if (taskProcessor.isDiscoverStage()) {
                    guiTopBar.getProgressIndicatorDiscover().setVisible(true);
                }
                if (taskProcessor.isTestStage()) {
                    guiTopBar.getProgressIndicatorTested().setVisible(true);
                }
                guiTestsRun.clear();
            }
        } else if (GuiMenu.PRINT.equals((String) arg1)) {
            if (guiMenu.getPrintFile() != null && pbstTest != null && pbstTest.getWebPages() != null && pbstTest.getWebPages().values() != null) {

                if (taskProcessor != null) {
                    taskProcessor.getDiscoverLauncher().updatePBST();
                    taskProcessor.getTestLauncher().updatePBST();
                }

                Report report = new Report(pbstTest);

                report.create();

                report.save(guiMenu.getPrintFile());

                if (Desktop.isDesktopSupported()) {
                    try {
                        Desktop.getDesktop().open(guiMenu.getPrintFile());
                    } catch (IOException ex) {
                    }
                }
            }

            guiTestsConfiguration.getGlassPane().setVisible(false);
        } else if (GUI.STOP_DISCOVER_STAGE.equals((String) arg1)) {
            guiTopBar.getProgressIndicatorDiscover().setVisible(false);
            guiTopBar.getProgressIndicatorTested().setVisible(true);
        } else if (GUI.STOP_TEST_STAGE.equals((String) arg1)) {
            guiTopBar.getProgressIndicatorTested().setVisible(false);
        } else if (GuiMenu.STOP.equals((String) arg1)) {
            taskProcessor.stop();
        } else if (GUI.UPDATE.equals((String) arg1)) {
            taskProcessor.getDiscoverLauncher().updatePBST();
            taskProcessor.getTestLauncher().updatePBST();

            guiTestsConfiguration.getGlassPane().setVisible(false);
            guiTopBar.getProgressIndicatorDiscover().setVisible(false);
            guiTopBar.getProgressIndicatorTested().setVisible(false);

            if (endTime == 0) {
                endTime = System.currentTimeMillis();

                System.out.println("DEMOROU " + ((endTime - startTime) / 1000) + " segundos");
            }
        }
    }
}
