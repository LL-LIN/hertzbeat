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

package org.apache.hertzbeat.manager.service.impl;

import com.fasterxml.jackson.core.type.TypeReference;

import static org.apache.hertzbeat.common.constants.ExportFileConstants.ExcelFile.FILE_SUFFIX;
import static org.apache.hertzbeat.common.constants.ExportFileConstants.ExcelFile.TYPE;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.hertzbeat.common.entity.manager.Tag;
import org.apache.hertzbeat.common.util.JsonUtil;
import org.apache.hertzbeat.common.util.export.ExcelExportUtils;
import org.apache.hertzbeat.manager.dao.TagDao;
import org.apache.hertzbeat.manager.service.TagService;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.CellType;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.apache.poi.ss.util.CellRangeAddress;
import org.apache.poi.ss.util.RegionUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Configure the import and export EXCEL format
 */
@Slf4j
@RequiredArgsConstructor
@Service
public class ExcelImExportServiceImpl extends AbstractImExportServiceImpl{

    @Autowired
    private TagDao tagDao;

    /**
     * Export file type
     * @return file type
     */
    @Override
    public String type() {
        return TYPE;
    }

    /**
     * Get Export File Name
     * @return file name
     */
    @Override
    public String getFileName() {
        return fileNamePrefix() + FILE_SUFFIX;
    }

    /**
     * Parsing an input stream into a form
     * @param is input stream
     * @return form
     */
    @Override
    public List<ExportMonitorDTO> parseImport(InputStream is) {
        try (Workbook workbook = WorkbookFactory.create(is)) {
            Sheet sheet = workbook.getSheetAt(0);

            List<ExportMonitorDTO> monitors = new ArrayList<>();
            List<Integer> startRowList = new ArrayList<>();

            for (Row row : sheet) {
                if (row.getRowNum() == 0) {
                    continue;
                }
                String name = getCellValueAsString(row.getCell(0));
                if (StringUtils.isNotBlank(name)) {
                    startRowList.add(row.getRowNum());
                    MonitorDTO monitor = extractMonitorDataFromRow(row);
                    String metrics = getCellValueAsString(row.getCell(11));
                    boolean detected = getCellValueAsBoolean(row.getCell(12));
                    ExportMonitorDTO exportMonitor = new ExportMonitorDTO();
                    exportMonitor.setMonitor(monitor);
                    monitors.add(exportMonitor);
                    if (StringUtils.isNotBlank(metrics)) {
                        List<String> metricList = Arrays.stream(metrics.split(",")).collect(Collectors.toList());
                        exportMonitor.setMetrics(metricList);
                    }
                    exportMonitor.setDetected(detected);
                }
            }

            List<List<ParamDTO>> paramsList = new ArrayList<>();

            for (int i = 0; i < startRowList.size(); i++) {
                int startRowIndex = startRowList.get(i);
                int endRowIndex = (i + 1 < startRowList.size()) ? startRowList.get(i + 1) : sheet.getLastRowNum() + 1;
                List<ParamDTO> params = new ArrayList<>();

                for (int j = startRowIndex; j < endRowIndex; j++) {
                    Row row = sheet.getRow(j);
                    if (row == null) {
                        continue;
                    }
                    ParamDTO param = extractParamDataFromRow(row);
                    if (param != null) {
                        params.add(param);
                    }
                }

                paramsList.add(params);
            }
            for (int i = 0; i < monitors.size(); i++) {
                monitors.get(i).setParams(paramsList.get(i));
            }
            return monitors;
        } catch (IOException e) {
            throw new RuntimeException("Failed to parse monitor data", e);
        }
    }

    @Transactional
    public MonitorDTO extractMonitorDataFromRow(Row row) {
        MonitorDTO monitor = new MonitorDTO();

        monitor.setName(getCellValueAsString(row.getCell(0)));
        monitor.setApp(getCellValueAsString(row.getCell(1)));
        monitor.setHost(getCellValueAsString(row.getCell(2)));
        monitor.setIntervals(getCellValueAsInteger(row.getCell(3)));
        monitor.setStatus(getCellValueAsByte(row.getCell(4)));
        monitor.setDescription(getCellValueAsString(row.getCell(5)));

        String tagsString = getCellValueAsString(row.getCell(6));
        if (StringUtils.isNotBlank(tagsString)) {
            List<Tag> parsedTags;
            try {
                // 解析标签字符串并去重
                parsedTags = parseTagString(tagsString).stream()
                                                       .distinct()
                                                       .toList();
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("标签格式错误: " + e.getMessage());
            }
            List<Tag> existingTags = new ArrayList<>();
            List<Tag> newTags = new ArrayList<>();
            // 分离已存在和新增的标签
            for (Tag tag : parsedTags) {
                Optional<Tag> existingTagOpt = tagDao.findTagByNameAndTagValue(tag.getName(), tag.getTagValue());
                if (existingTagOpt.isPresent()) {
                    existingTags.add(existingTagOpt.get());
                } else {
                    // 设置新标签的类型和ID
                    tag.setType((byte) 1);
                    tag.setId(null);
                    newTags.add(tag);
                }
            }
            // 批量保存新标签
            if (!newTags.isEmpty()) {
                try {
                    List<Tag> savedTags = tagDao.saveAll(newTags);
                    existingTags.addAll(savedTags);
                } catch (Exception e) {
                    throw new IllegalArgumentException("保存标签失败: " + e.getMessage(), e);
                }
            }
            // 设置合并后的标签到Monitor
            monitor.setTagBindings(existingTags);
        }
        monitor.setCollector(getCellValueAsString(row.getCell(7)));


        return monitor;
    }

    private List<Tag> parseTagString(String input) {
        try {
            // 1. 预处理输入格式
            String normalized = input.trim();

            // 使用项目JSON工具校验格式
            if (!JsonUtil.isJsonStr(normalized)) {
                // 自动修复常见格式问题
                normalized = normalized
                        .replaceAll("}\\s*,\\s*\\{", "},{")  // 修复对象分隔符
                        .replaceAll("'", "\"")                 // 替换单引号
                        .replaceAll("(\\w+):", "\"$1\":");     // 自动补全属性引号
            }
            // 包裹为数组格式
            if (!normalized.startsWith("[")) {
                normalized = "[" + normalized + "]";
            }
            // 2. 使用项目JSON工具解析
            List<Tag> tags = JsonUtil.fromJson(normalized, new TypeReference<>() {
            });

            // 3. 校验必要字段
            if (tags == null) {
                throw new IllegalArgumentException("Invalid tag format");
            }
            tags.forEach(tag -> {
                if (StringUtils.isBlank(tag.getName())) {
                    throw new IllegalArgumentException("Tag name cannot be empty");
                }
                if (tag.getTagValue() == null) {
                    tag.setTagValue(""); // 保证非null
                }
            });

            return tags;
        } catch (Exception e) {
            throw new IllegalArgumentException("标签解析失败: " + e.getMessage());
        }
    }

    private ParamDTO extractParamDataFromRow(Row row) {
        String fieldName = getCellValueAsString(row.getCell(8));
        if (StringUtils.isNotBlank(fieldName)) {
            ParamDTO param = new ParamDTO();
            param.setField(fieldName);
            param.setType(getCellValueAsByte(row.getCell(9)));
            param.setValue(getCellValueAsString(row.getCell(10)));
            return param;
        }
        return null;
    }

    private String getCellValueAsString(Cell cell) {
        if (cell == null) {
            return null;
        }
        return switch (cell.getCellType()) {
            case STRING -> cell.getStringCellValue();
            case NUMERIC -> {
                double value = cell.getNumericCellValue();
                String s = String.valueOf(value);
                // 移除末尾的 .0
                if (s.endsWith(".0")) {
                    s = s.substring(0, s.length() - 2);
                }
                yield s;
            }
            default -> null;
        };
    }
    
    private boolean getCellValueAsBoolean(Cell cell) {
        if (cell == null) {
            return false;
        }
        if (Objects.requireNonNull(cell.getCellType()) == CellType.BOOLEAN) {
            return cell.getBooleanCellValue();
        }
        return false;
    }

    private Integer getCellValueAsInteger(Cell cell) {
        if (cell == null) {
            return null;
        }
        if (Objects.requireNonNull(cell.getCellType()) == CellType.NUMERIC) {
            return (int) cell.getNumericCellValue();
        }
        return null;
    }

    private Byte getCellValueAsByte(Cell cell) {
        if (cell == null) {
            return null;
        }
        if (Objects.requireNonNull(cell.getCellType()) == CellType.NUMERIC) {
            return (byte) cell.getNumericCellValue();
        }
        return null;
    }

    /**
     * Export Configuration to Output Stream
     * @param monitorList config list
     * @param os          output stream
     */
    @Override
    public void writeOs(List<ExportMonitorDTO> monitorList, OutputStream os) {
        try {

            Workbook workbook = WorkbookFactory.create(true);
            String sheetName = "Export Monitor";
            Sheet sheet = ExcelExportUtils.setSheet(sheetName, workbook, MonitorDTO.class);
            // set cell style
            CellStyle cellStyle = ExcelExportUtils.setCellStyle(workbook);

            // foreach monitor, each monitor object corresponds to a row of data
            int rowIndex = 1;
            for (ExportMonitorDTO monitor : monitorList) {
                // get monitor information
                MonitorDTO monitorDTO = monitor.getMonitor();
                // get monitor parameters
                List<ParamDTO> paramList = monitor.getParams();
                // get monitor metrics
                List<String> metricList = monitor.getMetrics();
                // merge monitor information and parameter information into one row
                for (int i = 0; i < Math.max(paramList.size(), 1); i++) {
                    Row row = sheet.createRow(rowIndex++);
                    if (i == 0) {
                        // You need to fill in the monitoring information only once
                        Cell nameCell = row.createCell(0);
                        nameCell.setCellValue(monitorDTO.getName());
                        nameCell.setCellStyle(cellStyle);
                        Cell appCell = row.createCell(1);
                        appCell.setCellValue(monitorDTO.getApp());
                        appCell.setCellStyle(cellStyle);
                        Cell hostCell = row.createCell(2);
                        hostCell.setCellValue(monitorDTO.getHost());
                        hostCell.setCellStyle(cellStyle);
                        Cell intervalsCell = row.createCell(3);
                        intervalsCell.setCellValue(monitorDTO.getIntervals());
                        intervalsCell.setCellStyle(cellStyle);
                        Cell statusCell = row.createCell(4);
                        statusCell.setCellValue(monitorDTO.getStatus());
                        statusCell.setCellStyle(cellStyle);
                        Cell descriptionCell = row.createCell(5);
                        descriptionCell.setCellValue(monitorDTO.getDescription());
                        descriptionCell.setCellStyle(cellStyle);
                        // 修改 writeOs 方法中的标签导出部分：
                        Cell tagsCell = row.createCell(6);
                        String tagDisplay = monitorDTO.getTags()
                                                      .stream()
                                                      .map(tagId -> {
                                                          Tag tag = tagDao.findById(tagId)
                                                                          .orElse(null);
                                                          return tag != null
                                                                  ?
                                                                  String.format("{\"name\":\"%s\",\"tagValue\":\"%s\"}",
                                                                                tag.getName(), tag.getTagValue())
                                                                  : "";
                                                      })
                                                      .filter(StringUtils::isNotBlank)
                                                      .collect(Collectors.joining(","));
                        tagsCell.setCellValue(tagDisplay);
                        tagsCell.setCellStyle(cellStyle);
                        Cell collectorCell = row.createCell(7);
                        collectorCell.setCellValue(monitorDTO.getCollector());
                        collectorCell.setCellStyle(cellStyle);
                        if (metricList != null && i < metricList.size()) {
                            Cell metricCell = row.createCell(11);
                            metricCell.setCellValue(String.join(",", metricList));
                            metricCell.setCellStyle(cellStyle);
                        }
                        Cell detectedCell = row.createCell(12);
                        detectedCell.setCellValue(monitor.getDetected() != null && monitor.getDetected());
                        detectedCell.setCellStyle(cellStyle);
                    }
                    // Fill in parameter information
                    if (i < paramList.size()) {
                        ParamDTO paramDTO = paramList.get(i);
                        Cell fieldCell = row.createCell(8);
                        fieldCell.setCellValue(paramDTO.getField());
                        fieldCell.setCellStyle(cellStyle);
                        Cell typeCell = row.createCell(9);
                        typeCell.setCellValue(paramDTO.getType());
                        typeCell.setCellStyle(cellStyle);
                        Cell valueCell = row.createCell(10);
                        valueCell.setCellValue(paramDTO.getValue());
                        valueCell.setCellStyle(cellStyle);
                    }
                }
                if (CollectionUtils.isNotEmpty(paramList)) {
                    RegionUtil.setBorderTop(BorderStyle.THICK, new CellRangeAddress(rowIndex - paramList.size(), rowIndex - 1, 0, 10), sheet);
                    RegionUtil.setBorderBottom(BorderStyle.THICK, new CellRangeAddress(rowIndex - paramList.size(), rowIndex - 1, 0, 10), sheet);
                    RegionUtil.setBorderLeft(BorderStyle.THICK, new CellRangeAddress(rowIndex - paramList.size(), rowIndex - 1, 0, 10), sheet);
                    RegionUtil.setBorderRight(BorderStyle.THICK, new CellRangeAddress(rowIndex - paramList.size(), rowIndex - 1, 0, 10), sheet);
                }
            }
            workbook.write(os);
            os.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
