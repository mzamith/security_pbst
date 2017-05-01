package org.feup.ses.pbst.GUI;

import javafx.geometry.Pos;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.ScrollPane.ScrollBarPolicy;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.text.Font;
import javafx.scene.text.FontWeight;
import javafx.scene.text.Text;

public class GuiUtils {

    public static GridPane getMenuButton(String text, Image image, int width, int height, double fitPercentagem, String id) {
        GridPane gp = new GridPane();
        gp.setId(id);
        gp.setMinSize(width, height);
        gp.setMaxSize(width, height);
        gp.setAlignment(Pos.CENTER);

        HBox boxImage = new HBox();
        boxImage.setAlignment(Pos.CENTER);
        ImageView img = new ImageView();
        img.setFitWidth(height * fitPercentagem);
        img.setFitHeight(height * fitPercentagem);
        img.setImage(image);
        boxImage.getChildren().add(img);
        gp.add(boxImage, 0, 0);

        if (text != null && !"".equals(text.trim())) {
            HBox boxText = new HBox();
            boxText.setAlignment(Pos.CENTER);
            Text t = new Text(text);
            t.setFont(Font.font("Times", FontWeight.NORMAL, 14));
            boxText.getChildren().add(t);
            gp.add(boxText, 0, 1);
        }

        return gp;
    }

    public static ScrollPane getScrollPane(ScrollBarPolicy hPolicyValue, ScrollBarPolicy vPolicyValue, double width, double height) {
        ScrollPane scrollContent = new ScrollPane();
        scrollContent.setHbarPolicy(hPolicyValue);
        scrollContent.setVbarPolicy(vPolicyValue);
        if (width > 0) {
            scrollContent.setMinWidth(width);
            scrollContent.setMaxWidth(width);
        }
        if (height > 0) {
            scrollContent.setMinHeight(height);
            scrollContent.setMaxHeight(height);
        }

        return scrollContent;
    }

}
