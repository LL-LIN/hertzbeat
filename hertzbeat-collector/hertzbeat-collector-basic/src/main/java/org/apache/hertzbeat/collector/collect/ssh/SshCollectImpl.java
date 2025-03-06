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

package org.apache.hertzbeat.collector.collect.ssh;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.apache.hertzbeat.collector.collect.AbstractCollect;
import org.apache.hertzbeat.collector.collect.common.cache.CacheIdentifier;
import org.apache.hertzbeat.collector.collect.common.cache.ConnectionCommonCache;
import org.apache.hertzbeat.collector.collect.common.cache.SshConnect;
import org.apache.hertzbeat.collector.collect.common.ssh.CommonSshBlacklist;
import org.apache.hertzbeat.collector.collect.common.ssh.CommonSshClient;
import org.apache.hertzbeat.collector.constants.CollectorConstants;
import org.apache.hertzbeat.collector.dispatch.DispatchConstants;
import org.apache.hertzbeat.collector.util.CollectUtil;
import org.apache.hertzbeat.collector.util.PrivateKeyUtils;
import org.apache.hertzbeat.common.constants.CommonConstants;
import org.apache.hertzbeat.common.entity.job.Metrics;
import org.apache.hertzbeat.common.entity.job.protocol.SshProtocol;
import org.apache.hertzbeat.common.entity.message.CollectRep;
import org.apache.hertzbeat.common.util.CommonUtil;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.channel.ClientChannel;
import org.apache.sshd.client.channel.ClientChannelEvent;
import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.channel.exception.SshChannelOpenException;
import org.apache.sshd.common.util.io.output.NoCloseOutputStream;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.springframework.util.StringUtils;

/**
 * Ssh protocol collection implementation
 */
@Slf4j
public class SshCollectImpl extends AbstractCollect {

    private static final String PARSE_TYPE_ONE_ROW = "oneRow";
    private static final String PARSE_TYPE_MULTI_ROW = "multiRow";
    private static final String PARSE_TYPE_NETCAT = "netcat";
    private static final String PARSE_TYPE_LOG = "log";

    private static final int DEFAULT_TIMEOUT = 10_000;
    private final ConnectionCommonCache<CacheIdentifier, SshConnect> connectionCommonCache;

    public SshCollectImpl() {
        connectionCommonCache = new ConnectionCommonCache<>();
    }

    @Override
    public void preCheck(Metrics metrics) throws IllegalArgumentException {
        if (metrics == null || metrics.getSsh() == null) {
            throw new IllegalArgumentException("ssh collect must has ssh params");
        }
    }

    @Override
    public void collect(CollectRep.MetricsData.Builder builder, long monitorId, String app, Metrics metrics) {

        long startTime = System.currentTimeMillis();
        SshProtocol sshProtocol = metrics.getSsh();
        boolean reuseConnection = Boolean.parseBoolean(sshProtocol.getReuseConnection());
        boolean useProxy = Boolean.parseBoolean(sshProtocol.getUseProxy());
        int timeout = CollectUtil.getTimeout(sshProtocol.getTimeout(), DEFAULT_TIMEOUT);
        ClientChannel channel = null;
        ClientSession clientSession = null;
        try {
            clientSession = getConnectSession(sshProtocol, timeout, reuseConnection, useProxy);
            if (CommonSshBlacklist.isCommandBlacklisted(sshProtocol.getScript())) {
                builder.setCode(CollectRep.Code.FAIL);
                builder.setMsg("The command is blacklisted: " + sshProtocol.getScript());
                log.warn("The command is blacklisted: {}", sshProtocol.getScript());
                return;
            }
            channel = clientSession.createExecChannel(sshProtocol.getScript());
            ByteArrayOutputStream response = new ByteArrayOutputStream();
            channel.setOut(response);
            channel.setErr(new NoCloseOutputStream(System.err));
            channel.open().verify(timeout);
            List<ClientChannelEvent> list = new ArrayList<>();
            list.add(ClientChannelEvent.CLOSED);
            Collection<ClientChannelEvent> waitEvents = channel.waitFor(list, timeout);
            if (waitEvents.contains(ClientChannelEvent.TIMEOUT)) {
                //  A cancel signal needs to be sent if the execution times out, otherwise the session cannot be closed promptly
                int cancelSignal = 3;
                channel.getInvertedIn().write(cancelSignal);
                channel.getInvertedIn().flush();
                throw new SocketTimeoutException("Failed to retrieve command result in time: " + sshProtocol.getScript());
            }
            Long responseTime = System.currentTimeMillis() - startTime;
            String result = response.toString();
            if (!StringUtils.hasText(result)) {
                builder.setCode(CollectRep.Code.FAIL);
                builder.setMsg("ssh shell response data is null");
                return;
            }
            switch (sshProtocol.getParseType()) {
                case PARSE_TYPE_LOG -> parseResponseDataByLog(result, metrics.getAliasFields(), builder, responseTime);
                case PARSE_TYPE_NETCAT -> parseResponseDataByNetcat(result, metrics.getAliasFields(), builder, responseTime);
                case PARSE_TYPE_ONE_ROW -> parseResponseDataByOne(result, metrics.getAliasFields(), builder, responseTime);
                case PARSE_TYPE_MULTI_ROW -> parseResponseDataByMulti(result, metrics.getAliasFields(), builder, responseTime);
                default -> {
                    builder.setCode(CollectRep.Code.FAIL);
                    builder.setMsg("Ssh collect not support this parse type: " + sshProtocol.getParseType());
                }
            }
        } catch (ConnectException connectException) {
            String errorMsg = CommonUtil.getMessageFromThrowable(connectException);
            log.info(errorMsg);
            builder.setCode(CollectRep.Code.UN_CONNECTABLE);
            builder.setMsg("The peer refused to connect: service port does not listening or firewall: " + errorMsg);
        } catch (SshException sshException) {
            Throwable throwable = sshException.getCause();
            if (throwable instanceof SshChannelOpenException) {
                log.warn("Remote ssh server no more session channel, please increase sshd_config MaxSessions.");
            }
            String errorMsg = CommonUtil.getMessageFromThrowable(sshException);
            builder.setCode(CollectRep.Code.UN_CONNECTABLE);
            builder.setMsg("Peer ssh connection failed: " + errorMsg);
        } catch (IOException ioException) {
            String errorMsg = CommonUtil.getMessageFromThrowable(ioException);
            log.info(errorMsg);
            builder.setCode(CollectRep.Code.UN_CONNECTABLE);
            builder.setMsg("Peer io connection failed: " + errorMsg);
        } catch (Exception exception) {
            String errorMsg = CommonUtil.getMessageFromThrowable(exception);
            log.warn(errorMsg, exception);
            builder.setCode(CollectRep.Code.FAIL);
            builder.setMsg(errorMsg);
        } finally {
            if (channel != null && channel.isOpen()) {
                try {
                    // Close the SSH channel with the 'false' parameter to ensure the session is not kept alive.
                    long st = System.currentTimeMillis();
                    channel.close(false).addListener(future ->
                            log.debug("channel is closed in {} ms", System.currentTimeMillis() - st));
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
            if (clientSession != null && !reuseConnection && !useProxy) {
                try {
                    clientSession.close();
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
    }

    @Override
    public String supportProtocol() {
        return DispatchConstants.PROTOCOL_SSH;
    }

    private void parseResponseDataByLog(String result, List<String> aliasFields, CollectRep.MetricsData.Builder builder, Long responseTime) {
        String[] lines = result.split("\n");
        if (lines.length + 1 < aliasFields.size()) {
            log.error("ssh response data not enough: {}", result);
            return;
        }
        for (String line : lines) {
            CollectRep.ValueRow.Builder valueRowBuilder = CollectRep.ValueRow.newBuilder();
            for (String alias : aliasFields) {
                if (CollectorConstants.RESPONSE_TIME.equalsIgnoreCase(alias)) {
                    valueRowBuilder.addColumns(responseTime.toString());
                } else {
                    valueRowBuilder.addColumns(line);
                }
            }
            builder.addValues(valueRowBuilder.build());
        }
    }

    private void parseResponseDataByNetcat(String result, List<String> aliasFields, CollectRep.MetricsData.Builder builder, Long responseTime) {
        String[] lines = result.split("\n");
        if (lines.length + 1 < aliasFields.size()) {
            log.error("ssh response data not enough: {}", result);
            return;
        }
        boolean contains = lines[0].contains("=");
        Map<String, String> mapValue = Arrays.stream(lines)
                .map(item -> {
                    if (contains) {
                        return item.split("=");
                    } else {
                        return item.split("\t");
                    }
                })
                .filter(item -> item.length == 2)
                .collect(Collectors.toMap(x -> x[0], x -> x[1]));

        CollectRep.ValueRow.Builder valueRowBuilder = CollectRep.ValueRow.newBuilder();
        for (String field : aliasFields) {
            String fieldValue = mapValue.get(field);
            valueRowBuilder.addColumns(Objects.requireNonNullElse(fieldValue, CommonConstants.NULL_VALUE));
        }
        builder.addValues(valueRowBuilder.build());
    }

    private void parseResponseDataByOne(String result, List<String> aliasFields, CollectRep.MetricsData.Builder builder, Long responseTime) {
        String[] lines = result.split("\n");
        if (lines.length + 1 < aliasFields.size()) {
            log.error("ssh response data not enough: {}", result);
            return;
        }
        CollectRep.ValueRow.Builder valueRowBuilder = CollectRep.ValueRow.newBuilder();
        int aliasIndex = 0;
        int lineIndex = 0;
        while (aliasIndex < aliasFields.size()) {
            if (CollectorConstants.RESPONSE_TIME.equalsIgnoreCase(aliasFields.get(aliasIndex))) {
                valueRowBuilder.addColumns(responseTime.toString());
            } else {
                if (lineIndex < lines.length) {
                    valueRowBuilder.addColumns(lines[lineIndex].trim());
                } else {
                    valueRowBuilder.addColumns(CommonConstants.NULL_VALUE);
                }
                lineIndex++;
            }
            aliasIndex++;
        }
        builder.addValues(valueRowBuilder.build());
    }

    private void parseResponseDataByMulti(String result, List<String> aliasFields,
                                          CollectRep.MetricsData.Builder builder, Long responseTime) {
        String[] lines = result.split("\n");
        if (lines.length <= 1) {
            log.error("ssh response data only has header: {}", result);
            return;
        }
        String[] fields = lines[0].split(" ");
        Map<String, Integer> fieldMapping = new HashMap<>(fields.length);
        for (int i = 0; i < fields.length; i++) {
            fieldMapping.put(fields[i].trim().toLowerCase(), i);
        }
        for (int i = 1; i < lines.length; i++) {
            String[] values = lines[i].split(" ");
            CollectRep.ValueRow.Builder valueRowBuilder = CollectRep.ValueRow.newBuilder();
            for (String alias : aliasFields) {
                if (CollectorConstants.RESPONSE_TIME.equalsIgnoreCase(alias)) {
                    valueRowBuilder.addColumns(responseTime.toString());
                } else {
                    Integer index = fieldMapping.get(alias.toLowerCase());
                    if (index != null && index < values.length) {
                        valueRowBuilder.addColumns(values[index]);
                    } else {
                        valueRowBuilder.addColumns(CommonConstants.NULL_VALUE);
                    }
                }
            }
            builder.addValues(valueRowBuilder.build());
        }
    }

    private void removeConnectSessionCache(SshProtocol sshProtocol) {
        CacheIdentifier identifier = CacheIdentifier.builder()
                .ip(sshProtocol.getHost()).port(sshProtocol.getPort())
                .username(sshProtocol.getUsername()).password(sshProtocol.getPassword())
                .build();
        connectionCommonCache.removeCache(identifier);
    }

    private ClientSession getConnectSession(SshProtocol sshProtocol, int timeout, boolean reuseConnection, boolean useProxy)
            throws IOException, GeneralSecurityException {
        CacheIdentifier identifier = CacheIdentifier.builder()
                .ip(sshProtocol.getHost()).port(sshProtocol.getPort())
                .username(sshProtocol.getUsername()).password(sshProtocol.getPassword())
                .build();
        ClientSession clientSession = null;
        // When using ProxyJump, force connection reuse:
        // Apache MINA SSHD will pass the proxy password error to the target host in proxy scenarios, causing the first connection to fail.
        // Reusing connections can skip duplicate authentication and avoid this problem.
        if (reuseConnection || useProxy) {
            Optional<SshConnect> cacheOption = connectionCommonCache.getCache(identifier, true);
            if (cacheOption.isPresent()) {
                clientSession = cacheOption.get().getConnection();
                try {
                    if (clientSession == null || clientSession.isClosed() || clientSession.isClosing()) {
                        clientSession = null;
                        connectionCommonCache.removeCache(identifier);
                    }
                } catch (Exception e) {
                    log.warn(e.getMessage());
                    clientSession = null;
                    connectionCommonCache.removeCache(identifier);
                }
            }
            if (clientSession != null) {
                return clientSession;
            }
        }
        SshClient sshClient = CommonSshClient.getSshClient();
        HostConfigEntry proxyConfig = new HostConfigEntry();
        if (useProxy && StringUtils.hasText(sshProtocol.getProxyHost())) {
            String proxySpec = String.format("%s@%s:%d", sshProtocol.getProxyUsername(), sshProtocol.getProxyHost(), Integer.parseInt(sshProtocol.getProxyPort()));
            proxyConfig.setHostName(sshProtocol.getHost());
            proxyConfig.setHost(sshProtocol.getHost());
            proxyConfig.setPort(Integer.parseInt(sshProtocol.getPort()));
            proxyConfig.setUsername(sshProtocol.getUsername());
            proxyConfig.setProxyJump(proxySpec);

            // Apache SSHD requires the password for the proxy to be preloaded into the sshClient instance before connecting
            if (StringUtils.hasText(sshProtocol.getProxyPassword())) {
                sshClient.addPasswordIdentity(sshProtocol.getProxyPassword());
                log.debug("Loaded proxy server password authentication: {}@{}", sshProtocol.getProxyUsername(), sshProtocol.getProxyHost());
            }
            if (StringUtils.hasText(sshProtocol.getProxyPrivateKey())) {
                proxyConfig.setIdentities(List.of(sshProtocol.getProxyPrivateKey()));
                log.debug("Proxy private key loaded into HostConfigEntry");
            }
        }

        if (useProxy && StringUtils.hasText(sshProtocol.getProxyHost())) {
            try {
                clientSession = sshClient.connect(proxyConfig)
                                         .verify(timeout, TimeUnit.MILLISECONDS).getSession();
            }
            finally {
                sshClient.removePasswordIdentity(sshProtocol.getProxyPassword());
            }
        } else {
            clientSession = sshClient.connect(sshProtocol.getUsername(), sshProtocol.getHost(), Integer.parseInt(sshProtocol.getPort()))
                                     .verify(timeout, TimeUnit.MILLISECONDS).getSession();
        }
        if (StringUtils.hasText(sshProtocol.getPassword())) {
            clientSession.addPasswordIdentity(sshProtocol.getPassword());
        } else if (StringUtils.hasText(sshProtocol.getPrivateKey())) {
            var resourceKey = PrivateKeyUtils.writePrivateKey(sshProtocol.getHost(), sshProtocol.getPrivateKey());
            try (InputStream keyStream = new FileInputStream(resourceKey)) {
                Iterable<KeyPair> keyPairs = SecurityUtils.loadKeyPairIdentities(null, () -> resourceKey, keyStream, null);
                if (keyPairs != null) {
                    keyPairs.forEach(clientSession::addPublicKeyIdentity);
                } else {
                    log.error("Failed to load private key pairs from: {}", resourceKey);
                }
            } catch (IOException e) {
                log.error("Error reading private key file: {}", e.getMessage());
            }
        }  // else auth with localhost private public key certificates

        // auth
        if (!clientSession.auth().verify(timeout, TimeUnit.MILLISECONDS).isSuccess()) {
            clientSession.close();
            throw new IllegalArgumentException("ssh auth failed.");
        }
        if (reuseConnection || useProxy) {
            SshConnect sshConnect = new SshConnect(clientSession);
            connectionCommonCache.addCache(identifier, sshConnect);
        }
        return clientSession;
    }
}
