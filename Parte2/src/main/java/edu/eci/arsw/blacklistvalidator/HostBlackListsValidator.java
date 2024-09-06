package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import edu.eci.arsw.threads.SearchTask;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HostBlackListsValidator {

    public static final int BLACK_LIST_ALARM_COUNT = 5; 
    private final Object lock = new Object();
    private int totalOccurrences = 0;
    private boolean stopSearching = false;
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());

    public List<Integer> checkHost(String ipAddress, int threads) {
        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();
        LinkedList<Integer> mergedBlackListOccurrences = new LinkedList<>();
        List<SearchTask> searchThreads = new ArrayList<>();
        
        int totalLists = skds.getRegisteredServersCount();
        int baseSize = totalLists / threads;
        int remainder = totalLists % threads;
        int startIndex = 0;

        for (int i = 0; i < threads; i++) {
            int segmentSize = (i < remainder) ? baseSize + 1 : baseSize;
            int endIndex = startIndex + segmentSize - 1;

            SearchTask thread = new SearchTask(startIndex, endIndex, ipAddress, mergedBlackListOccurrences, this);
            searchThreads.add(thread);
            thread.start();

            startIndex = endIndex + 1;
        }

        synchronized (lock) {
            while (totalOccurrences < BLACK_LIST_ALARM_COUNT && !stopSearching) {
                try {
                    lock.wait(); // Espera hasta que se notifique que la búsqueda puede detenerse
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        // Esperar a que todos los hilos terminen su ejecución
        for (SearchTask thread : searchThreads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        if (totalOccurrences >= BLACK_LIST_ALARM_COUNT) {
            skds.reportAsNotTrustworthy(ipAddress);
        } else {
            skds.reportAsTrustworthy(ipAddress);
        }

        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{totalOccurrences, skds.getRegisteredServersCount()});
        
        return mergedBlackListOccurrences;
    }

    public void incrementOccurrences(int value) {
        synchronized (lock) {
            totalOccurrences += value;
            if (totalOccurrences >= BLACK_LIST_ALARM_COUNT) {
                stopSearching = true;
                lock.notifyAll(); // Notifica a todos los hilos que la búsqueda puede detenerse
            }
        }
    }

    public synchronized boolean shouldStopSearching() {
        return stopSearching;
    }
}
