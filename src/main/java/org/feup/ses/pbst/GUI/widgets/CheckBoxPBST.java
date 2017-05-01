package org.feup.ses.pbst.GUI.widgets;

import java.util.ArrayList;
import java.util.List;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.geometry.Insets;
import javafx.scene.control.CheckBox;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Pane;

public class CheckBoxPBST {

    private CheckBoxPBST group;
    private List<CheckBoxPBST> childs;
    private CheckBox button;
    private String name;

    public CheckBoxPBST(Pane parent, boolean disabled) {
        this(parent, "", disabled);
    }

    public CheckBoxPBST(Pane parent, String text, boolean disabled) {
        this(parent, text, false, disabled);
    }

    public CheckBoxPBST(Pane parent, String text, boolean bold, boolean disabled) {
        this(parent, text, bold, null, disabled);

        addListener();
    }

    public CheckBoxPBST(Pane parent, String text, boolean bold, CheckBoxPBST group, boolean disabled) {
        this.button = new CheckBox();
        button.setText(text);
        button.setPickOnBounds(false);
        button.setDisable(disabled);
        this.name = text;
        HBox hBox = new HBox();

        if (bold) {
            button.getStyleClass().add("bold");
            hBox.setPadding(new Insets(15, 0, 0, 5));
        } else {
            hBox.setPadding(new Insets(5, 0, 0, 25));
        }

        hBox.getChildren().add(button);

        this.group = group;

        parent.getChildren().add(hBox);

        addListener();
    }

    public CheckBoxPBST(CheckBox button) {
        this.button = button;

        addListener();
    }

    public CheckBoxPBST(Pane parent, String text, CheckBoxPBST group, boolean disabled) {
        this(parent, text, disabled);
        this.group = group;
    }

    public CheckBoxPBST(CheckBox button, CheckBoxPBST group) {
        this(button);
        this.group = group;
    }

    public CheckBoxPBST(Pane parent, String text, List<CheckBoxPBST> childs, boolean disabled) {
        this(parent, text, disabled);
        this.childs = childs;
    }

    public CheckBoxPBST(final CheckBox button, final List<CheckBoxPBST> childs) {
        this(button);
        this.childs = childs;
    }

    public CheckBoxPBST(Pane parent, String text, CheckBoxPBST group, List<CheckBoxPBST> childs, boolean disabled) {
        this(parent, text, group, disabled);
        this.childs = childs;
    }

    public CheckBoxPBST(CheckBox button, CheckBoxPBST group, List<CheckBoxPBST> childs) {
        this(button, group);
        this.childs = childs;
    }

    private void addListener() {
        button.setOnAction(new EventHandler<ActionEvent>() {

            @Override
            public void handle(ActionEvent event) {
                button.setIndeterminate(false);
                changeChilds(childs, button.isSelected());
                changeGroup(group);
            }
        });
    }

    private void changeChilds(List<CheckBoxPBST> childs, boolean selected) {
        if (childs != null && !childs.isEmpty()) {
            for (int i = 0; i < childs.size(); i++) {
                if (!childs.get(i).getButton().isDisable()) {
                    childs.get(i).getButton().setSelected(selected);
                    if (childs.get(i).getChilds() != null && !childs.get(i).getChilds().isEmpty()) {
                        changeChilds(childs.get(i).getChilds(), childs.get(i).getButton().isSelected());
                    }
                }
                changeGroup(childs.get(i).getGroup());
            }
        }
    }

    private void changeGroup(CheckBoxPBST group) {
        if (group != null && group.getChilds() != null) {
            int size = group.getChilds().size();
            int countUnselected = 0;
            int countSelected = 0;
            for (int i = 0; i < size; i++) {
                if (!group.getChilds().get(i).getButton().isSelected()) {
                    countUnselected++;
                } else if (group.getChilds().get(i).getButton().isSelected() && group.getChilds().get(i).getButton().isIndeterminate()) {
                    //DO nothing - just to skip counting increment
                } else {
                    countSelected++;
                }
            }
            if (countUnselected == size) {
                group.getButton().setSelected(false);
                group.getButton().setIndeterminate(false);
            } else if (countSelected == size) {
                group.getButton().setSelected(true);
                group.getButton().setIndeterminate(false);
            } else {
                group.getButton().setSelected(true);
                group.getButton().setIndeterminate(true);
            }

            changeGroup(group.getGroup());
        }
    }

    public void addChild(CheckBoxPBST child) {
        if (child != null) {
            if (this.childs == null) {
                this.childs = new ArrayList<CheckBoxPBST>();
            }

            this.childs.add(child);
        }
    }

    public void updateGroup(CheckBoxPBST group) {
        if (group != null) {
            changeGroup(group);
        }
    }

    public void addGroup(CheckBoxPBST group) {
        this.group = group;
    }

    public CheckBoxPBST getGroup() {
        return group;
    }

    public void setGroup(CheckBoxPBST group) {
        this.group = group;
    }

    public List<CheckBoxPBST> getChilds() {
        return childs;
    }

    public void setChilds(List<CheckBoxPBST> childs) {
        this.childs = childs;
    }

    public CheckBox getButton() {
        return button;
    }

    public void setButton(CheckBox button) {
        this.button = button;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
