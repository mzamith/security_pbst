package org.feup.ses.pbst.Utils;

import java.io.Serializable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

public class ConcurrentUrlTreeMap implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 1L;

    private ConcurrentMap<String, Object> concurrentMap;
    private AtomicLong count;

    public ConcurrentUrlTreeMap() {
        this.concurrentMap = new ConcurrentHashMap<String, Object>();
        this.count = new AtomicLong(0);
    }

    public void set(ConcurrentUrlTreeMap concurrentUrlTreeMap) {
        this.concurrentMap = concurrentUrlTreeMap.getConcurrentMap();
        this.count = concurrentUrlTreeMap.getCount();
    }

    public void clear() {
        this.concurrentMap.clear();
    }

    @SuppressWarnings("unchecked")
    public boolean addUrl(String url) {
        if (url == null || "".equals(url)) {
            return false;
        }

        String[] str1 = url.split("://");

        if (str1 == null || str1.length != 2) {
            return false;
        }

        str1[1] = str1[1].replace("?", "/");
        String[] str2 = str1[1].split("/");

        if (str2 == null || str2.length == 0) {
            return false;
        }

        if (concurrentMap.get(str1[0]) == null) {
            concurrentMap.putIfAbsent(str1[0], new ConcurrentHashMap<String, Object>());
        }

        ConcurrentMap<String, Object> map = (ConcurrentMap<String, Object>) concurrentMap.get(str1[0]);

        for (int i = 0; i < str2.length; i++) {
            if (i + 1 == str2.length) {
                if (map.get(str2[i]) == null) {
                    map.putIfAbsent(str2[i], new String(""));
                    count.incrementAndGet();
                    return true;
                } else {
                    return false;
                }
            } else {
                if (map.get(str2[i]) == null) {
                    map.putIfAbsent(str2[i], new ConcurrentHashMap<String, Object>());
                } else if (map.get(str2[i]) instanceof String) {
                    map.put(str2[i], new ConcurrentHashMap<String, Object>());
                }

                map = (ConcurrentMap<String, Object>) map.get(str2[i]);
            }
        }

        return false;
    }

    @SuppressWarnings("unchecked")
    public boolean contains(String url) {
        if (url == null || "".equals(url)) {
            return false;
        }

        String[] str1 = url.split("://");

        if (str1 == null || str1.length != 2) {
            return false;
        }

        String[] str2 = str1[1].split("/");

        if (str2 == null || str2.length == 0) {
            return false;
        }

        if (concurrentMap.get(str1[0]) == null) {
            return false;
        }

        ConcurrentMap<String, Object> map = (ConcurrentMap<String, Object>) concurrentMap.get(str1[0]);

        for (int i = 0; i < str2.length; i++) {
            if (i + 1 == str2.length) {
                if ("".equals(map.get(str2[i]))) {
                    return true;
                } else {
                    return false;
                }
            } else {
                if (map.get(str2[i]) == null) {
                    return false;
                }

                map = (ConcurrentMap<String, Object>) map.get(str2[i]);
            }
        }

        return false;
    }

    public ConcurrentMap<String, Object> getConcurrentMap() {
        return concurrentMap;
    }

    public AtomicLong getCount() {
        return count;
    }
}
