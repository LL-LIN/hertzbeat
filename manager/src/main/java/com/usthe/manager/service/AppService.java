package com.usthe.manager.service;

import com.usthe.common.entity.job.Job;
import com.usthe.manager.pojo.entity.ParamDefine;

import java.util.List;

/**
 * 监控类型管理接口
 *
 *
 */
public interface AppService {

    /**
     * 根据监控类型查询定义的参数结构
     * @param app 监控类型
     * @return 参数结构列表
     */
    List<ParamDefine> getAppParamDefines(String app);

    /**
     * 根据监控类型名称获取监控结构定义
     * @param app 监控类型名称
     * @return 监控结构定义
     * @throws IllegalArgumentException 当不存在即不支持对应名称的监控类型时抛出
     */
    Job getAppDefine(String app) throws IllegalArgumentException;
}
