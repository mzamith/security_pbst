package org.feup.ses.pbst.GUI;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.Observable;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Pos;
import javafx.scene.control.ToggleButton;
import javafx.scene.image.Image;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.feup.ses.pbst.GUI.widgets.CheckBoxPBST;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.TestResult;
import org.feup.ses.pbst.patternTests.WebPage;

public class GuiMenu extends Observable {

    public final static double MENU_WIDTH = 420;

    public final static String SHOW = "show";
    public final static String HIDE = "hide";
    public final static String NEW = "new";
    public final static String OPEN = "open";
    public final static String SAVE = "save";
    public final static String PRINT = "print";
    public final static String RUN = "run";
    public final static String STOP = "stop";

    private Stage stage;
    private GridPane menuPane;
    private TestConfAndResult pbstTest;

    private ToggleButton menu;

    private boolean canSave = false;

    private File printFile;

    public GuiMenu(final Stage stage, TestConfAndResult pbstTest) {
        this.stage = stage;
        this.pbstTest = pbstTest;

        createMenuPane();

        canSave = true;
    }

    public HBox getMenuBox() {
        HBox menuBox = new HBox(10);
        menuBox.setPrefSize(MENU_WIDTH, GUI.GUI_TOP_PANE_HEIGHT);
        menuBox.setAlignment(Pos.CENTER_LEFT);
        addCloseMenuAction(menuBox);

        menu = new ToggleButton();
        menu.setId("menu-button");
        menu.getStyleClass().clear();
        menu.getStylesheets().add(getClass().getClassLoader().getResource("application.css").toExternalForm());
        menu.setMinSize(32, menuBox.getPrefHeight() - 2);
        menu.setMaxSize(32, menuBox.getPrefHeight() - 2);
        menu.setAlignment(Pos.CENTER);
        menu.setOnAction(new EventHandler<ActionEvent>() {
            @Override
            public void handle(ActionEvent event) {
                if (menuPane.isVisible()) {
                    menuPane.setVisible(false);
                    menu.getStyleClass().clear();
                    setChanged();
                    notifyObservers(HIDE);
                } else {
                    menuPane.setVisible(true);
                    menu.getStyleClass().add("menu-active");
                    setChanged();
                    notifyObservers(SHOW);
                }
            }
        });

        menuBox.getChildren().add(menu);

        return menuBox;
    }

    private GridPane createMenuPane() {
        menuPane = new GridPane();
        menuPane.setId("menu");
        menuPane.setMinWidth(305);
        menuPane.setMaxWidth(305);
        menuPane.setMinHeight(275);
        menuPane.setMaxHeight(275);
        menuPane.setVisible(false);
        menuPane.setAlignment(Pos.TOP_LEFT);
        addCloseMenuAction(menuPane);

        menuPane.getStylesheets().add(getClass().getClassLoader().getResource("application.css").toExternalForm());

        addMenuElements();

        return menuPane;
    }

    private void addMenuElements() {
        GridPane newTest = GuiUtils.getMenuButton("New", new Image("images/novoTeste.png"), 100, 90, 0.5, "button_image_text");
        newTest.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                pbstTest.clear();
                printFile = null;
                setChanged();
                notifyObservers(NEW);
            }
        });
        menuPane.add(newTest, 0, 0);

        GridPane openTest = GuiUtils.getMenuButton("Open", new Image("images/abrirTeste.png"), 100, 90, 0.5, "button_image_text");
        openTest.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                openPBST();
            }
        });
        menuPane.add(openTest, 1, 0);

        GridPane save = GuiUtils.getMenuButton("Save", new Image("images/guardarTeste.png"), 100, 90, 0.5, "button_image_text");
        save.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                savePBST();

                setChanged();
                notifyObservers(SHOW);
            }
        });
        menuPane.add(save, 2, 0);

        GridPane print = GuiUtils.getMenuButton("Print to PDF", new Image("images/impressora.png"), 100, 90, 0.5, "button_image_text");
        print.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                FileChooser fileChooser = new FileChooser();
                fileChooser.setTitle("Create PDF");

                FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PDF files (*.pdf)", "*.pdf");
                fileChooser.getExtensionFilters().add(extFilter);

                printFile = fileChooser.showSaveDialog(stage);

                setChanged();
                notifyObservers(PRINT);
            }
        });
        menuPane.add(print, 0, 1);

        GridPane runTest = GuiUtils.getMenuButton("Run tests", new Image("images/executar.png"), 100, 90, 0.5, "button_image_text");
        runTest.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                updateBeforeSave(pbstTest.getGuiPatterns().getChilds());

                setChanged();
                notifyObservers(RUN);
            }
        });
        menuPane.add(runTest, 1, 1);

        GridPane stopTest = GuiUtils.getMenuButton("Stop tests", new Image("images/stop.png"), 100, 90, 0.5, "button_image_text");
        stopTest.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                setChanged();
                notifyObservers(STOP);
            }
        });
        menuPane.add(stopTest, 2, 1);

        GridPane exit = GuiUtils.getMenuButton(null, new Image("images/sair.png"), 100, 90, 0.5, "button_image_text");
        exit.setOnMouseClicked(new EventHandler<MouseEvent>() {

            @Override
            public void handle(MouseEvent event) {
                setChanged();
                notifyObservers(STOP);

                stage.close();
            }
        });
        menuPane.add(exit, 2, 2);
    }

    private void openPBST() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open test");

        FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PBST files (*.pbst)", "*.pbst");
        fileChooser.getExtensionFilters().add(extFilter);

        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {
            try {
                FileInputStream fin = new FileInputStream(file);
                ObjectInputStream ois = new ObjectInputStream(fin);
                TestConfAndResult temp = (TestConfAndResult) ois.readObject();

                pbstTest.setLoginPage(temp.getLoginPage());
                pbstTest.setHomePage(temp.getHomePage());
                pbstTest.setFailPage(temp.getFailPage());
                pbstTest.setPatterns(temp.getPatterns());
                pbstTest.setCredentials(temp.getCredentials());

                pbstTest.setPrivateUrlsTested(temp.getPrivateUrlsTested());
                pbstTest.setPublicUrlsTested(temp.getPublicUrlsTested());

                pbstTest.setPrivateUrlsToTest(temp.getPrivateUrlsToTest());
                pbstTest.setPublicUrlsToTest(temp.getPublicUrlsToTest());

                pbstTest.setTotalSelectedToBeTested(temp.getTotalSelectedToBeTested() != null ? temp.getTotalSelectedToBeTested() : 0);
                pbstTest.setTotalAccessed(temp.getTotalAccessed() != null ? temp.getTotalAccessed() : 0);
                pbstTest.setTotalDiscovered(temp.getTotalDiscovered() != null ? temp.getTotalDiscovered() : 0);
                pbstTest.setTotalNotAccessible(temp.getTotalNotAccessible() != null ? temp.getTotalNotAccessible() : 0);
                pbstTest.setTotalPrivate(temp.getTotalPrivate() != null ? temp.getTotalPrivate() : 0);
                pbstTest.setTotalPublic(temp.getTotalPublic() != null ? temp.getTotalPublic() : 0);
                pbstTest.setTotalPrivateTested(temp.getTotalPrivateTested() != null ? temp.getTotalPrivateTested() : 0);
                pbstTest.setTotalPublicTested(temp.getTotalPublicTested() != null ? temp.getTotalPublicTested() : 0);

                pbstTest.setWebPages(temp.getWebPages());

                if (pbstTest.getWebPages() != null) {
                    for (WebPage wp : pbstTest.getWebPages().values()) {
                        for (TestResult tr : wp.getTestResults().values()) {
                            tr.setState(tr.getState());
                        }
                    }
                }

                pbstTest.setTotalUrlsDiscovered(temp.getTotalUrlsDiscovered());
                pbstTest.setUrlsToProcess(temp.getUrlsToProcess());
                pbstTest.setUrlsToTest(temp.getUrlsToTest());

                setChanged();
                notifyObservers(OPEN);

                ois.close();

            } catch (ClassNotFoundException e) {
                e.printStackTrace();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }

    private void savePBST() {
        if (canSave) {
            FileChooser fileChooser = new FileChooser();
            fileChooser.setTitle("Save test");

            FileChooser.ExtensionFilter extFilter = new FileChooser.ExtensionFilter("PBST files (*.pbst)", "*.pbst");
            fileChooser.getExtensionFilters().add(extFilter);

            File file = fileChooser.showSaveDialog(stage);
            if (file != null) {
                try {
                    FileOutputStream fout = new FileOutputStream(file);
                    ObjectOutputStream oos = new ObjectOutputStream(fout);
                    updateBeforeSave(pbstTest.getGuiPatterns().getChilds());
                    oos.writeObject(pbstTest);
                    oos.flush();
                    oos.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
    }

    private void updateBeforeSave(List<CheckBoxPBST> allPatterns) {
        if (allPatterns != null && !allPatterns.isEmpty()) {
            for (CheckBoxPBST child : allPatterns) {
                pbstTest.updatePattern(child.getName(), child.getButton().isSelected());
                updateBeforeSave(child.getChilds());
            }
        }
    }

    public void addCloseMenuAction(Pane pane) {
        pane.addEventHandler(MouseEvent.MOUSE_CLICKED, new EventHandler<MouseEvent>() {
            @Override
            public void handle(MouseEvent event) {
                if (menuPane.isVisible()) {
                    menuPane.setVisible(false);
                    menu.getStyleClass().clear();
                    setChanged();
                    notifyObservers(HIDE);
                }
            }
        });
    }

    public GridPane getMenuPane() {
        return menuPane;
    }

    public TestConfAndResult getPbstTest() {
        return pbstTest;
    }

    public void setPbstTest(TestConfAndResult pbstTest) {
        this.pbstTest = pbstTest;
    }

    public File getPrintFile() {
        return printFile;
    }
}
