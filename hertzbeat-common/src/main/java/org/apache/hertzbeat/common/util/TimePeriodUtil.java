/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hertzbeat.common.util;

import java.time.Duration;
import java.time.Period;
import java.time.temporal.TemporalAmount;
import lombok.extern.slf4j.Slf4j;

/**
 * time util
 */
@Slf4j
public final class TimePeriodUtil {

    private TimePeriodUtil() {
    }

    /**
     * parse tokenTime to TemporalAmount
     * @param tokenTime eg: "1m", "5M", "3D", "30m", "2h", "1Y", "3W"
     * @return TemporalAmount
     */
    public static TemporalAmount parseTokenTime(String tokenTime) {

        if (tokenTime == null || tokenTime.length() < 2) {
            log.error("tokenTime is invalid");
            return null;
        }

        if (Character.isUpperCase(tokenTime.charAt(tokenTime.length() - 1))) {
            return Period.parse("P" + tokenTime);
        } else {
            return Duration.parse("PT" + tokenTime);
        }
    }

    /**
     * transform any timestamp to milliseconds
     * @param timestamp timestamp
     * @return milliseconds
     */
    public static long normalizeToMilliseconds(Object timestamp) {
        if (timestamp instanceof String timestampStr) {
            // string type, may be second, millisecond or decimal second
            // eg: "1672531199000", "1672531199", "1672531199.123"
            if (timestampStr.contains(".")) {
                // contains decimal point, parse as second timestamp
                double seconds = Double.parseDouble(timestampStr);
                return (long) (seconds * 1000);
            } else {
                // integer form, determine second or millisecond
                long numericTimestamp = Long.parseLong(timestampStr);
                return convertNumericTimestamp(numericTimestamp);
            }
        } else if (timestamp instanceof Number) {
            // number eg Integer、Long、Double
            if (timestamp instanceof Double || timestamp instanceof Float) {
                // float type, treat as second timestamp
                double seconds = ((Number) timestamp).doubleValue();
                return (long) (seconds * 1000);
            } else {
                // integer type, directly determine second or millisecond
                long numericTimestamp = ((Number) timestamp).longValue();
                return convertNumericTimestamp(numericTimestamp);
            }
        } else {
            throw new IllegalArgumentException("Not support this timestamp type: " + timestamp.getClass().getName());
        }
    }

    private static long convertNumericTimestamp(long numericTimestamp) {
        if (String.valueOf(numericTimestamp).length() <= 10) {
            return numericTimestamp * 1000;
        } else {
            return numericTimestamp;
        }
    }
}
