package com.cryptocarver.ui;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.*;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;

import java.util.function.Consumer;

/**
 * Side Panel - Hierarchical navigation with search
 * Matches "Module Explorer" visual target
 */
public class SidePanel extends VBox {

    private final TextField searchField;
    private final TreeView<String> navigationTree;
    private final Button collapseButton;
    private Consumer<String> onItemSelected;
    private TreeItem<String> rootItem;

    public SidePanel() {
        // Panel styling via CSS
        setMinWidth(280);
        setMaxWidth(280);
        setPrefWidth(280);
        getStyleClass().add("side-panel");

        // Header with search and collapse button
        HBox header = new HBox(8);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(8));
        header.getStyleClass().add("side-panel-header");

        // Search icon (simple text for now, could be icon)
        Label searchIcon = new Label("🔍");
        searchIcon.setStyle("-fx-text-fill: #7f8c8d; -fx-font-size: 14px;");

        // Search field
        searchField = new TextField();
        searchField.setPromptText("Search");
        searchField.getStyleClass().add("search-field");
        HBox.setHgrow(searchField, Priority.ALWAYS);

        // Search functionality
        searchField.textProperty().addListener((obs, old, newVal) -> filterTree(newVal));

        // Collapse button (optional, can stay or go depending on visual preference)
        collapseButton = new Button("«");
        collapseButton.setTooltip(new Tooltip("Collapse panel"));
        collapseButton.getStyleClass().add("button"); // Standard button
        collapseButton.setStyle("-fx-background-color: transparent; -fx-text-fill: #7f8c8d; -fx-font-weight: bold;");
        collapseButton.setOnAction(e -> collapse());

        header.getChildren().addAll(searchIcon, searchField, collapseButton);

        // Navigation TreeView
        navigationTree = new TreeView<>();
        navigationTree.setShowRoot(false);
        navigationTree.getStyleClass().add("navigation-tree");

        VBox.setVgrow(navigationTree, Priority.ALWAYS);

        // Item selection handler
        navigationTree.getSelectionModel().selectedItemProperty().addListener((obs, old, newVal) -> {
            if (newVal != null && newVal.isLeaf()) {
                String selected = newVal.getValue();
                System.out.println("TreeView item selected: " + selected);
                if (onItemSelected != null) {
                    onItemSelected.accept(selected);
                }
            }
        });

        getChildren().addAll(header, navigationTree);

        // Initialize with default content (Keys)
        updateContent(NavigationRail.Section.KEYS);
    }

    public void updateContent(NavigationRail.Section section) {
        rootItem = new TreeItem<>(section.getLabel());

        switch (section) {
            case CIPHER:
                buildCipherTree();
                break;
            case GENERIC:
                buildGenericTree();
                break;
            case AUTHENTICATION:
                buildAuthenticationTree();
                break;
            case KEYS:
                buildKeysTree();
                break;
            case CERTIFICATES:
                buildCertificatesTree();
                break;
            case JOSE:
                buildJOSETree();
                break;
            case PAYMENTS:
                buildPaymentsTree();
                break;
            case ASN1:
                buildASN1Tree();
                break;
            case HISTORY:
                buildHistoryTree();
                break;
            case SEARCH:
                buildSearchTree();
                break;

        }

        navigationTree.setRoot(rootItem);
        expandAll(rootItem);
    }

    private void buildCipherTree() {
        TreeItem<String> symmetric = new TreeItem<>("Symmetric");
        symmetric.getChildren().addAll(
                new TreeItem<>("Symmetric Ciphers"));

        TreeItem<String> asymmetric = new TreeItem<>("Asymmetric");
        asymmetric.getChildren().addAll(
                new TreeItem<>("Asymmetric Ciphers"));

        rootItem.getChildren().addAll(symmetric, asymmetric);
    }

    private void buildAuthenticationTree() {
        rootItem.getChildren().addAll(
                new TreeItem<>("Digital Signatures"),
                new TreeItem<>("Message Authentication Codes"));
    }

    private void buildGenericTree() {
        rootItem.getChildren().addAll(
                new TreeItem<>("Hashing"),
                new TreeItem<>("Manual Conversion"),
                new TreeItem<>("File Conversion"),
                new TreeItem<>("Random Number Generator"),
                new TreeItem<>("Check Digits"),
                new TreeItem<>("Modular Arithmetic"));
    }

    private void buildKeysTree() {
        TreeItem<String> symmetric = new TreeItem<>("Symmetric");
        symmetric.getChildren().addAll(
                new TreeItem<>("Key Generation"),
                new TreeItem<>("Validation & KCV"),
                new TreeItem<>("Key Sharing (XOR Split/Combine)"),
                new TreeItem<>("Key Derivation (KDF)"),
                new TreeItem<>("TR-31 Key Blocks"));

        TreeItem<String> asymmetric = new TreeItem<>("Asymmetric");
        asymmetric.getChildren().addAll(
                new TreeItem<>("RSA Key Generation"),
                new TreeItem<>("ECDSA Key Generation"),
                new TreeItem<>("DSA Key Generation"),
                new TreeItem<>("EdDSA Key Generation"));

        rootItem.getChildren().addAll(symmetric, asymmetric);
    }

    private void buildCertificatesTree() {
        rootItem.getChildren().addAll(
                new TreeItem<>("Generate Certificate"),
                new TreeItem<>("Parse Certificate"),
                new TreeItem<>("Validate Certificate"),
                new TreeItem<>("Certificate Chain"),
                new TreeItem<>("CMS/PKCS#7 Operations"));
    }

    private void buildJOSETree() {
        rootItem.getChildren().addAll(
                new TreeItem<>("JWT (Signed)"),
                new TreeItem<>("JWE (Encrypted)"),
                new TreeItem<>("JWK (Keys)"),
                new TreeItem<>("JWA (Algorithms)"),
                new TreeItem<>("Token Inspector"));
    }

    private void buildPaymentsTree() {
        rootItem.getChildren().addAll(
                new TreeItem<>("Clear PIN Blocks"),
                new TreeItem<>("Encrypted PIN Blocks"),
                new TreeItem<>("PIN Generation"),
                new TreeItem<>("CVV Operations"),
                new TreeItem<>("EMV Operations"));
    }

    private void buildASN1Tree() {
        rootItem.getChildren().addAll(
                new TreeItem<>("Decode ASN.1"),
                new TreeItem<>("Encode ASN.1"));
    }

    private void buildHistoryTree() {
        rootItem.getChildren().addAll(
                new TreeItem<>("Recent Operations"),
                new TreeItem<>("Saved Sessions"),
                new TreeItem<>("Export History"));
    }

    private void buildSearchTree() {
        rootItem.getChildren().add(
                new TreeItem<>("Quick search across all operations"));
    }

    private void expandAll(TreeItem<?> item) {
        if (item != null && !item.isLeaf()) {
            item.setExpanded(true);
            for (TreeItem<?> child : item.getChildren()) {
                expandAll(child);
            }
        }
    }

    private void filterTree(String filter) {
        if (filter == null || filter.trim().isEmpty()) {
            // Show current section items
            navigationTree.setRoot(rootItem);
            expandAll(rootItem);
        } else {
            // Global Search: Search across ALL operations
            TreeItem<String> allOperationsRoot = new TreeItem<>("Search Results");
            populateAllItems(allOperationsRoot);

            String lowerFilter = filter.toLowerCase();
            TreeItem<String> filteredRoot = new TreeItem<>("Search Results");

            if (filterItems(allOperationsRoot, filteredRoot, lowerFilter)) {
                navigationTree.setRoot(filteredRoot);
                expandAll(filteredRoot);
            } else {
                // No matches found
                navigationTree.setRoot(new TreeItem<>("No operations found"));
            }
        }
    }

    // Helper to populate a root with ALL available operations for global search
    private void populateAllItems(TreeItem<String> targetRoot) {
        TreeItem<String> originalRoot = this.rootItem;
        this.rootItem = targetRoot; // Temporarily direct build methods to targetRoot

        try {
            buildKeysTree();
            buildCipherTree();
            buildAuthenticationTree();
            buildCertificatesTree();
            buildJOSETree();
            buildGenericTree();
            buildPaymentsTree();
            buildASN1Tree();
        } finally {
            this.rootItem = originalRoot; // Restore original root
        }
    }

    private boolean filterItems(TreeItem<String> source, TreeItem<String> target, String filter) {
        boolean hasMatch = false;

        for (TreeItem<String> child : source.getChildren()) {
            TreeItem<String> newChild = new TreeItem<>(child.getValue());
            boolean childHasMatch = false;

            if (child.isLeaf()) {
                if (child.getValue().toLowerCase().contains(filter)) {
                    childHasMatch = true;
                }
            } else {
                if (filterItems(child, newChild, filter)) {
                    childHasMatch = true;
                }
            }

            if (childHasMatch) {
                target.getChildren().add(newChild);
                hasMatch = true;
            }
        }

        return hasMatch;
    }

    private void collapse() {
        setVisible(false);
        setManaged(false);
    }

    public void setOnItemSelected(Consumer<String> handler) {
        this.onItemSelected = handler;
    }
}
