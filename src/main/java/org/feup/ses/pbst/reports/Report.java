package org.feup.ses.pbst.reports;

import java.awt.Color;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDPageContentStream.AppendMode;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.feup.ses.pbst.Enums.PatternEnum;
import org.feup.ses.pbst.Enums.TestResultEnum;
import org.feup.ses.pbst.TestConfAndResult;
import org.feup.ses.pbst.patternTests.TestResult;
import org.feup.ses.pbst.patternTests.Vulnerability;
import org.feup.ses.pbst.patternTests.WebPage;

public class Report {

    private final int PAGE_TOP_POSITION_Y = 760;

    private String title;
    private PDDocument document;
    private PDPageContentStream stream;

    private PDFont titleFont;
    private PDFont defaultFont;
    private PDFont fontException;

    private PDPage currentPage;
    private int currentPageIndex;
    private int cursorPosY;

    private TestConfAndResult pbstTest;
    private Map<String, WebPage> webPages;

    public Report(final TestConfAndResult pbstTest) {
        this.pbstTest = pbstTest;
        this.webPages = this.pbstTest.getWebPages();

        document = new PDDocument();

        titleFont = PDType1Font.HELVETICA_BOLD;
        defaultFont = PDType1Font.TIMES_ROMAN;

        try {
            InputStream fontStream = new FileInputStream("c:/Windows/Fonts/ARIALUNI.TTF");
            fontException = PDType0Font.load(document, fontStream);
        } catch (IOException e) {
            e.printStackTrace();
        }

        title = "PBST Report";
        currentPageIndex = 0;
    }

    public void save(File file) {
        if (file != null) {
            try {
                if (file.exists()) {
                    file.delete();
                }
                document.save(file.getAbsolutePath());
                document.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void create() {
        Map<PatternEnum, TestResult> globalResults = generateGlobalResult();

        try {
            String baseURL = pbstTest.getHomePage() != null ? pbstTest.getHomePage() : pbstTest.getLoginPage();
            if (baseURL == null) {
                baseURL = "";
            }
            baseURL = baseURL.substring(0, baseURL.lastIndexOf("/") + 1);
            create(baseURL, globalResults);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void create(String baseURL, Map<PatternEnum, TestResult> globalResults) throws IOException {
        newPage();
        addTitle();
        cursorPosY = (PAGE_TOP_POSITION_Y - 30);

        addText(25, cursorPosY, titleFont, 14, baseURL, false, Color.black);
        drawLine(25, (cursorPosY -= 5), 580);

        addText(25, (cursorPosY -= 15), titleFont, 11, "Discovered URLs", false, Color.black);
        addText(140, cursorPosY, defaultFont, 12, "" + pbstTest.getTotalDiscovered(), false, Color.black);

        addText(250, cursorPosY, titleFont, 11, "URLs selected to be tested", false, Color.black);
        addText(395, cursorPosY, defaultFont, 12, "" + pbstTest.getTotalSelectedToBeTested(), false, Color.black);

        addText(25, (cursorPosY -= 15), titleFont, 11, "Public URLs", false, Color.black);
        addText(140, cursorPosY, defaultFont, 12, "" + pbstTest.getTotalPublic(), false, Color.black);

        addText(250, cursorPosY, titleFont, 11, "Public URLs tested", false, Color.black);
        addText(395, cursorPosY, defaultFont, 12, "" + pbstTest.getTotalPublicTested(), false, Color.black);

        addText(25, (cursorPosY -= 15), titleFont, 11, "Private URLs", false, Color.black);
        addText(140, cursorPosY, defaultFont, 12, "" + pbstTest.getTotalPrivate(), false, Color.black);

        addText(250, cursorPosY, titleFont, 11, "Private URLs tested", false, Color.black);
        addText(395, cursorPosY, defaultFont, 12, "" + pbstTest.getTotalPrivateTested(), false, Color.black);

        addText(25, (cursorPosY -= 15), titleFont, 11, "Not accessible URLs", false, Color.black);
        addText(140, cursorPosY, defaultFont, 12, "" + pbstTest.getTotalNotAccessible(), false, Color.black);

        cursorPosY -= 25;
        drawBox(25, cursorPosY, 555, 20, true);
        addText(30, (cursorPosY -= 15), titleFont, 14, "PATTERN RESULTS", true, Color.black);

        Map<PatternEnum, TestResult> vulnerableResults = new HashMap<PatternEnum, TestResult>();
        Map<Vulnerability, List<String>> vulnerablePages = new HashMap<Vulnerability, List<String>>();

        for (String key : webPages.keySet()) {
            WebPage wp = webPages.get(key);
            if (wp.isVulnerable()) {
                for (Vulnerability v : wp.getVulnerabilities()) {
                    if (vulnerablePages.get(v) == null) {
                        vulnerablePages.put(v, new ArrayList<String>());
                    }
                    vulnerablePages.get(v).add(wp.getUrlPath());
                }
            }
        }

        for (PatternEnum pattern : PatternEnum.VALUES) {
            TestResult tr = globalResults.get(pattern);

            Color color = Color.blue;

            if (tr.getState().equals(TestResultEnum.SECURE)) {
                color = Color.green;
            } else if (tr.getState().equals(TestResultEnum.VULNERABLE)) {
                color = Color.red;
                vulnerableResults.put(pattern, tr);
            }

            if (cursorPosY < 70) {
                newPage();
                cursorPosY = PAGE_TOP_POSITION_Y + 10;
                drawBox(25, cursorPosY, 555, 20, true);
                addText(30, (cursorPosY -= 15), titleFont, 14, "PATTERN RESULTS", true, Color.black);
                addText(550, cursorPosY, titleFont, 10, "Cont.", true, Color.black);
            }

            addText(30, (cursorPosY -= 20), titleFont, 11, pattern.getLiteral(), false, Color.black);
            addText(250, cursorPosY, titleFont, 11, tr.getState().getName(), false, color);
        }

        cursorPosY -= 25;
        drawBox(25, cursorPosY, 555, 20, true);
        addText(30, (cursorPosY -= 15), titleFont, 14, "VULNERABILITIES BY PATTERNS", true, Color.black);

        for (PatternEnum pattern : PatternEnum.VALUES) {
            if (vulnerableResults.get(pattern) == null) {
                continue;
            }

            if (cursorPosY < 70) {
                newPage();
                cursorPosY = PAGE_TOP_POSITION_Y + 10;
                drawBox(25, cursorPosY, 555, 20, true);
                addText(30, (cursorPosY -= 15), titleFont, 14, "VULNERABILITIES BY PATTERNS", true, Color.black);
                addText(550, cursorPosY, titleFont, 10, "Cont.", true, Color.black);
            }

            addText(30, (cursorPosY -= 20), titleFont, 11, pattern.getLiteral(), false, Color.black);

            List<Vulnerability> vulnerabilities = globalResults.get(pattern).getVulnerabilities();

            for (Vulnerability v : vulnerabilities) {
                if (cursorPosY < 70) {
                    newPage();
                    cursorPosY = PAGE_TOP_POSITION_Y + 10;
                    drawBox(25, cursorPosY, 555, 20, true);
                    addText(30, (cursorPosY -= 15), titleFont, 14, "VULNERABILITIES BY PATTERNS", true, Color.black);
                    addText(550, cursorPosY, titleFont, 10, "Cont.", true, Color.black);
                    addText(30, (cursorPosY -= 20), titleFont, 11, pattern.getLiteral(), false, Color.black);
                }

                addText(50, (cursorPosY -= 20), titleFont, 11, v.getName(), false, Color.black);

                for (String url : vulnerablePages.get(v)) {
                    if (cursorPosY < 70) {
                        newPage();
                        cursorPosY = PAGE_TOP_POSITION_Y + 10;
                        drawBox(25, cursorPosY, 555, 20, true);
                        addText(30, (cursorPosY -= 15), titleFont, 14, "VULNERABILITIES BY PATTERNS", true, Color.black);
                        addText(550, cursorPosY, titleFont, 10, "Cont.", true, Color.black);
                        addText(30, (cursorPosY -= 20), titleFont, 11, pattern.getLiteral(), false, Color.black);
                        addText(50, (cursorPosY -= 20), titleFont, 11, v.getName(), false, Color.black);
                    }

                    addText(80, (cursorPosY -= 15), defaultFont, 9, url, false, Color.black);
                }

                cursorPosY -= 5;
            }
        }
    }

    private Map<PatternEnum, TestResult> generateGlobalResult() {
        Map<PatternEnum, TestResult> mapTestResults = new HashMap<PatternEnum, TestResult>();

        for (PatternEnum pattern : PatternEnum.VALUES) {
            mapTestResults.put(pattern, new TestResult("", pattern, TestResultEnum.NOT_TESTED));
        }

        if (webPages != null && !webPages.isEmpty()) {
            for (WebPage wp : webPages.values()) {
                for (PatternEnum pattern : wp.getTestResults().keySet()) {
                    if (TestResultEnum.NOT_TESTED_VALUE == mapTestResults.get(pattern).getState().getValue()
                            || TestResultEnum.VULNERABLE_VALUE == wp.getTestResults().get(pattern).getState().getValue()) {
                        mapTestResults.get(pattern).setState(wp.getTestResults().get(pattern).getState());
                        if (mapTestResults.get(pattern).getVulnerabilities() == null) {
                            mapTestResults.get(pattern).setVulnerabilities(new ArrayList<Vulnerability>());
                        }
                        for (Vulnerability v : wp.getTestResults().get(pattern).getVulnerabilities()) {
                            if (!mapTestResults.get(pattern).getVulnerabilities().contains(v)) {
                                mapTestResults.get(pattern).getVulnerabilities().add(v);
                            }
                        }
                    }
                }
            }
        }

        return mapTestResults;
    }

    private void newPage() throws IOException {
        document.addPage(new PDPage());
        currentPage = document.getPage(currentPageIndex++);

        addPagePBST();
        addPageNum();
        drawLine(25, 30, 585);
        cursorPosY = PAGE_TOP_POSITION_Y;
    }

    private void addTitle() {
        addText(25, cursorPosY, titleFont, 24, title, false, Color.black);
    }

    private void addPagePBST() {
        addText(30, 20, titleFont, 10, "Pattern Based Security Testing", false, Color.black);
    }

    private void addPageNum() {
        addText(550, 20, titleFont, 10, "Pag. " + currentPageIndex, false, Color.black);
    }

    private void addText(int x, int y, PDFont font, int fontSize, String text, boolean boxTitle, Color color) {
        if (text != null) {
            try {
                stream = new PDPageContentStream(document, currentPage, AppendMode.APPEND, false);
                stream.setFont(font, fontSize);
                stream.beginText();
                stream.newLineAtOffset(x, y);
                if (boxTitle) {
                    stream.setNonStrokingColor(255, 255, 255);
                } else {
                    stream.setNonStrokingColor(color);
                }
                try {
                    stream.showText(text);
                } catch (IllegalArgumentException iae) {
                    stream.setFont(fontException, fontSize - 2);
                    stream.showText(text);
                }
                stream.endText();
                stream.setNonStrokingColor(0, 0, 0);
                stream.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

//	private List<String> splitText(String text, int splitSize){
//		List<String> list = new ArrayList<String>();
//
//		if(text.length() <= splitSize){
//			list.add(text);
//			return list;
//		}
//
//		int i = 0;
//		while(i < text.length()){
//			list.add(text.substring(i, Math.min(i+splitSize, text.length())));
//			i += splitSize;
//		}
//
//		return list;
//	}
    private void drawLine(int x, int y, int width) {
        try {
            stream = new PDPageContentStream(document, currentPage, AppendMode.APPEND, false);
            stream.moveTo(x, y);
            stream.lineTo(width, y);
            stream.closeAndStroke();
            stream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void drawBox(int x, int y, int width, int height, boolean fill) {
        try {
            float[] rectX = new float[]{x, x + width, x + width, x};
            float[] rectY = new float[]{y, y, y - height, y - height};
            stream = new PDPageContentStream(document, currentPage, AppendMode.APPEND, false);
            stream.moveTo(rectX[0], rectY[0]);
            for (int i = 0; i < 4; i++) {
                stream.lineTo(rectX[i], rectY[i]);
            }
            if (fill) {
                stream.closeAndFillAndStroke();
            } else {
                stream.closePath();
            }
            stream.stroke();
            stream.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
