package edu.eci.arsw.threads;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import edu.eci.arsw.blacklistvalidator.HostBlackListsValidator;

import java.util.List;

public class SearchTask extends Thread {
    private final int startRange;
    private final int endRange;
    private final String ipAddress;
    private final List<Integer> blacklistOccurrences;
    private final HostBlackListsValidator validator;

    public SearchTask(int startRange, int endRange, String ipAddress, List<Integer> blacklistOccurrences, HostBlackListsValidator validator) {
        this.startRange = startRange;
        this.endRange = endRange;
        this.ipAddress = ipAddress;
        this.blacklistOccurrences = blacklistOccurrences;
        this.validator = validator;
    }

    @Override
    public void run() {
        HostBlacklistsDataSourceFacade blacklistDataSource = HostBlacklistsDataSourceFacade.getInstance();
        for (int i = startRange; i <= endRange; i++) {
            if (validator.shouldStopSearching()) {
                break;
            }

            if (blacklistDataSource.isInBlackListServer(i, ipAddress)) {
                synchronized (blacklistOccurrences) {
                    blacklistOccurrences.add(i);
                }
                validator.incrementOccurrences(1);

                if (validator.shouldStopSearching()) {
                    break;
                }
            }
        }
    }
}
