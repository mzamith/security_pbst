package org.feup.ses.pbst.GUI;

import java.util.Observable;
import java.util.Observer;
import javafx.application.Platform;
import javafx.event.Event;
import javafx.event.EventHandler;
import javafx.geometry.Bounds;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.geometry.Rectangle2D;
import javafx.scene.Group;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.Tooltip;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.HBox;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;

public class GuiTopBar extends Observable implements Observer {

    public static final String TIMEOUT = "timeout";
    public static final String TAG = "guiTopBar";

    private Rectangle2D primaryScreenBounds;
    private Integer connectionsTimeout;
    private Integer discoverStopValue;

    private Text timeout;
    private Text discoverStop;
    private ProgressBar progressBarDiscover;
    private ProgressIndicator progressIndicatorDiscover;
    private Text percentageDiscover;
    private ProgressBar progressBarTested;
    private ProgressIndicator progressIndicatorTested;
    private Text percentageTested;

    private Text discoveredCount;
    private Text publicCount;
    private Text privateCount;
    private Text notAccessibleCount;

    private Text toBeTestedCount;
    private Text testedPublicCount;
    private Text testedPrivateCount;

    public GuiTopBar(final Rectangle2D primaryScreenBounds) {
        this.primaryScreenBounds = primaryScreenBounds;
        this.connectionsTimeout = GuiTestsConfiguration.DEFAULT_TIMEOUT;
        this.discoverStopValue = GuiTestsConfiguration.DEFAULT_DISCOVERING_STOP;
    }

    public HBox getBarBox() {
        HBox barBox = new HBox(30);
        barBox.setPrefSize(primaryScreenBounds.getWidth() - GuiMenu.MENU_WIDTH, GUI.GUI_TOP_PANE_HEIGHT);
        barBox.setMinHeight(GUI.GUI_TOP_PANE_HEIGHT);
        barBox.setAlignment(Pos.CENTER);

        VBox vBox = new VBox(0);
        vBox.setPrefHeight(GUI.GUI_TOP_PANE_HEIGHT);
        vBox.setMinWidth(230);
        vBox.setMaxWidth(230);

        HBox timeoutBox = new HBox(5);
        timeoutBox.setAlignment(Pos.CENTER_LEFT);
        timeout = new Text("" + connectionsTimeout);
        timeoutBox.getChildren().addAll(new Text("Connections timeout:"), timeout, new Text("Seconds"));

        HBox stopBox = new HBox(5);
        stopBox.setAlignment(Pos.CENTER_LEFT);
        discoverStop = new Text("" + discoverStopValue);
        stopBox.getChildren().addAll(new Text("Stop discovering after discover:"), discoverStop, new Text("URLs"));

        vBox.getChildren().add(timeoutBox);
        vBox.getChildren().add(stopBox);

        HBox blueBox = createSemaphoreBox("/images/bolaAzul.png", (discoveredCount = new Text("")), "Discovered URLs", 50);
        HBox blueToBeTestedBox = createSemaphoreBox("/images/bolaAzul2.png", (toBeTestedCount = new Text("")), "URLs to be tested", 50);

        VBox uriDTBox = new VBox(2);
        uriDTBox.setAlignment(Pos.CENTER_RIGHT);
        HBox uriDiscoveredBox = new HBox(5);
        uriDiscoveredBox.setPrefHeight(GUI.GUI_TOP_PANE_HEIGHT);
        uriDiscoveredBox.setAlignment(Pos.CENTER_LEFT);
        uriDiscoveredBox.setMinSize(320, 13);
        uriDiscoveredBox.setMaxSize(320, 13);
        Text uriDiscoveredLabel = new Text("Accessed URLs");
        uriDiscoveredBox.getChildren().add(uriDiscoveredLabel);

        StackPane barDiscover = new StackPane();
        progressBarDiscover = new ProgressBar(1.0);
        progressBarDiscover.setId("pbBlue");
        progressBarDiscover.setProgress(0.0);
        progressBarDiscover.setMinSize(200, 13);
        progressBarDiscover.setMaxSize(200, 13);
        percentageDiscover = new Text();
        barDiscover.getChildren().addAll(progressBarDiscover, percentageDiscover);
        uriDiscoveredBox.getChildren().add(barDiscover);
        Group g = new Group();
        progressIndicatorDiscover = new ProgressIndicator();
        progressIndicatorDiscover.setPrefSize(13, 13);
        progressIndicatorDiscover.setVisible(false);
        g.getChildren().add(progressIndicatorDiscover);
        uriDiscoveredBox.getChildren().add(g);

        HBox uriTestedBox = new HBox(5);
        uriTestedBox.setPrefHeight(GUI.GUI_TOP_PANE_HEIGHT);
        uriTestedBox.setAlignment(Pos.CENTER_LEFT);
        uriTestedBox.setMinSize(320, 13);
        uriTestedBox.setMaxSize(320, 13);
        Text uriTestedLabel = new Text("    Tested URLs");
        uriTestedBox.getChildren().add(uriTestedLabel);

        StackPane barTested = new StackPane();
        progressBarTested = new ProgressBar(1.0);
        progressBarTested.setId("pbGreen");
        progressBarTested.setProgress(0.0);
        progressBarTested.setMinSize(201, 13);
        progressBarTested.setMaxSize(201, 13);
        progressBarTested.setPadding(new Insets(0, 0, 0, 1));
        percentageTested = new Text();
        percentageTested.setTranslateX(1);
        barTested.getChildren().addAll(progressBarTested, percentageTested);
        uriTestedBox.getChildren().add(barTested);
        Group g2 = new Group();
        progressIndicatorTested = new ProgressIndicator();
        progressIndicatorTested.setPrefSize(13, 13);
        progressIndicatorTested.setVisible(false);
        g2.getChildren().add(progressIndicatorTested);
        uriTestedBox.getChildren().add(g2);

        uriDTBox.getChildren().addAll(uriDiscoveredBox, uriTestedBox);

        HBox greenBox = createSemaphoreBox("/images/bolaVerde.png", (publicCount = new Text("")), "Public URLs", 50);
        HBox redBox = createSemaphoreBox("/images/bolaVermelha.png", (privateCount = new Text("")), "Private URLs", 50);
        HBox blackBox = createSemaphoreBox("/images/bolaPreta.png", (notAccessibleCount = new Text("")), "Not accessible / Moved URLs", 50);

        HBox greenTestedBox = createSemaphoreBox("/images/bolaVerde2.png", (testedPublicCount = new Text("")), "Public URLs tested", 50);
        HBox redTestedBox = createSemaphoreBox("/images/bolaLaranja2.png", (testedPrivateCount = new Text("")), "Private URLs tested", 50);

        barBox.getChildren().addAll(vBox, blueBox, blueToBeTestedBox, uriDTBox, greenBox, redBox, blackBox, greenTestedBox, redTestedBox);

        return barBox;
    }

    private HBox createSemaphoreBox(String image, Text text, String message, double size) {
        HBox semaphoreBox = new HBox(5);
        semaphoreBox.setPrefHeight(GUI.GUI_TOP_PANE_HEIGHT);
        semaphoreBox.setAlignment(Pos.CENTER_LEFT);
        semaphoreBox.setMinWidth(size);
        semaphoreBox.setMaxWidth(size);
        ImageView dot = new ImageView(image);
        semaphoreBox.getChildren().add(dot);
        semaphoreBox.getChildren().add(text);

        Tooltip tooltip = new Tooltip(message);
        tooltip.setAutoHide(true);
        tooltip.setConsumeAutoHidingEvents(true);
        tooltip.setStyle("-fx-font-weight: bold");

        semaphoreBox.setOnMouseEntered(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                Bounds b = dot.localToScreen(dot.getBoundsInLocal());
                tooltip.show(dot, b.getMinX() - message.length() * 2.2, b.getMaxY() + 10);
            }
        });

        semaphoreBox.setOnMouseExited(new EventHandler<Event>() {

            @Override
            public void handle(Event event) {
                tooltip.hide();
            }
        });

        return semaphoreBox;
    }

    public void clear() {
        progressBarDiscover.setProgress(0.0);
        percentageDiscover.setText("0%");
        progressBarTested.setProgress(0.0);
        percentageTested.setText("0%");

        discoveredCount.setText("0");
        publicCount.setText("0");
        privateCount.setText("0");
        notAccessibleCount.setText("0");

        toBeTestedCount.setText("0");
        testedPublicCount.setText("0");
        testedPrivateCount.setText("0");
    }

    public void clearToNew() {
        getDiscoveredCount().setText("");
        getToBeTestedCount().setText("");
        getPublicCount().setText("");
        getPrivateCount().setText("");
        getNotAccessibleCount().setText("");
        getTestedPublicCount().setText("");
        getTestedPrivateCount().setText("");
        getPercentageDiscover().setText("");
        getPercentageTested().setText("");
        getProgressBarDiscover().setProgress(0.0);
        getProgressBarTested().setProgress(0.0);
    }

    public Integer getConnectionsTimeout() {
        return connectionsTimeout;
    }

    public ProgressBar getProgressBarDiscover() {
        return progressBarDiscover;
    }

    public void setProgressBarDiscover(ProgressBar progressBarDiscover) {
        this.progressBarDiscover = progressBarDiscover;
    }

    public ProgressBar getProgressBarTested() {
        return progressBarTested;
    }

    public void setProgressBarTested(ProgressBar progressBarTested) {
        this.progressBarTested = progressBarTested;
    }

    public Text getDiscoveredCount() {
        return discoveredCount;
    }

    public void setDiscoveredCount(Text discoveredCount) {
        this.discoveredCount = discoveredCount;
    }

    public Text getPublicCount() {
        return publicCount;
    }

    public void setPublicCount(Text publicCount) {
        this.publicCount = publicCount;
    }

    public Text getPrivateCount() {
        return privateCount;
    }

    public void setPrivateCount(Text privateCount) {
        this.privateCount = privateCount;
    }

    public Text getNotAccessibleCount() {
        return notAccessibleCount;
    }

    public void setNotAccessibleCount(Text notAccessibleCount) {
        this.notAccessibleCount = notAccessibleCount;
    }

    public ProgressIndicator getProgressIndicatorDiscover() {
        return progressIndicatorDiscover;
    }

    public ProgressIndicator getProgressIndicatorTested() {
        return progressIndicatorTested;
    }

    public Text getPercentageDiscover() {
        return percentageDiscover;
    }

    public Text getPercentageTested() {
        return percentageTested;
    }

    public Text getToBeTestedCount() {
        return toBeTestedCount;
    }

    public Text getTestedPublicCount() {
        return testedPublicCount;
    }

    public Text getTestedPrivateCount() {
        return testedPrivateCount;
    }

    @Override
    public void update(Observable arg0, Object arg1) {

        if (arg0 instanceof GUI && TIMEOUT.equals((String) arg1)) {
            connectionsTimeout = ((GUI) arg0).getConnectionsTimeout();
            timeout.setText("" + connectionsTimeout);

            discoverStopValue = ((GUI) arg0).getDiscoverinStopValue();
            discoverStop.setText("" + discoverStopValue);
        } else {
            if (arg0 instanceof TaskProcessor) {
                TaskProcessor tp = (TaskProcessor) arg0;

                if (tp != null) {
                    try {
                        Platform.runLater(new Runnable() {
                            public void run() {
                                if (TAG.equals((String) arg1)) {
                                    discoveredCount.setText("" + tp.getDiscoverLauncher().getDiscoveredURLs());
                                    publicCount.setText("" + tp.getDiscoverLauncher().getPublicURLs());
                                    privateCount.setText("" + tp.getDiscoverLauncher().getPrivateURLs());
                                    notAccessibleCount.setText("" + tp.getDiscoverLauncher().getNotAccessibleURLs());

                                    toBeTestedCount.setText("" + tp.getTestLauncher().getWebPages().size());
                                    testedPublicCount.setText("" + tp.getTestLauncher().getPublicUrlsTested().size());
                                    testedPrivateCount.setText("" + tp.getTestLauncher().getPrivateUrlsTested().size());

                                    if (tp.getDiscoverLauncher().getDiscoveredURLs() > 0) {
                                        int publicURLS = tp.getDiscoverLauncher().getPublicURLs();
                                        int privateURLS = tp.getDiscoverLauncher().getPrivateURLs();
                                        int notAccessibleURLS = tp.getDiscoverLauncher().getNotAccessibleURLs();

                                        int totalProcessed = publicURLS + privateURLS + notAccessibleURLS;
                                        double discovered = (double) totalProcessed / (double) tp.getDiscoverLauncher().getDiscoveredURLs();
                                        progressBarDiscover.progressProperty().set(discovered);
                                        percentageDiscover.setText("" + (Math.round(discovered * 100)) + "%");

                                        int tested = tp.getTestLauncher().getPublicUrlsTested().size() + tp.getTestLauncher().getPrivateUrlsTested().size();
                                        if (tested > 0) {
                                            double testedPercent = (double) tested / (double) (tp.getTestLauncher().getWebPages().size());
                                            progressBarTested.progressProperty().set(testedPercent);
                                            percentageTested.setText("" + (Math.round(testedPercent * 100)) + "%");
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
    }
}
