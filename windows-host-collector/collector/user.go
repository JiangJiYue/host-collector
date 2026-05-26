package collector

import (
	"context"
	"os"
	"strings"
	"windows-host-collector/models"
	"windows-host-collector/utils"
)

// UserCollector 用户和环境变量采集器
type UserCollector struct{}

func NewUserCollector() *UserCollector {
	return &UserCollector{}
}

func (uc *UserCollector) Name() string {
	return "user"
}

// UserCollectionResult 用户采集结果
type UserCollectionResult struct {
	Users   []models.LocalUserAccount    `json:"users"`
	EnvVars []models.EnvironmentVariable `json:"envVars"`
}

func (uc *UserCollector) Collect(ctx context.Context) (interface{}, error) {
	utils.Info("Collector", "开始采集用户信息...")

	type result struct {
		users []models.LocalUserAccount
		envs  []models.EnvironmentVariable
		err   error
	}

	resultChan := make(chan result, 1)

	go func() {
		var r result

		users, err := uc.collectUsers(ctx)
		if err != nil {
			utils.LogError("Collector", "用户账户采集失败: %v", err)
			users = []models.LocalUserAccount{}
		}
		r.users = users

		envs, err := uc.collectEnvironmentVariables(ctx)
		if err != nil {
			utils.LogError("Collector", "环境变量采集失败: %v", err)
			envs = []models.EnvironmentVariable{}
		}
		r.envs = envs

		resultChan <- r
	}()

	select {
	case r := <-resultChan:
		if r.err != nil {
			return nil, r.err
		}

		utils.Info("Collector", "用户信息采集完成: %d个用户, %d个环境变量", len(r.users), len(r.envs))

		return &UserCollectionResult{
			Users:   r.users,
			EnvVars: r.envs,
		}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// collectEnvironmentVariables 采集环境变量（跨平台）
func (uc *UserCollector) collectEnvironmentVariables(ctx context.Context) ([]models.EnvironmentVariable, error) {
	envVars := os.Environ()
	result := make([]models.EnvironmentVariable, 0, len(envVars))

	for _, env := range envVars {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 {
			result = append(result, models.EnvironmentVariable{
				Key:   parts[0],
				Value: parts[1],
			})
		}
	}

	return result, nil
}

// collectUsers 采集用户账户
func (uc *UserCollector) collectUsers(ctx context.Context) ([]models.LocalUserAccount, error) {
	return uc.collectPlatformUsers(ctx)
}

// getMockUsers 获取模拟用户数据
func (uc *UserCollector) getMockUsers() []models.LocalUserAccount {
	return []models.LocalUserAccount{
		{
			ID:             "user-1",
			Username:       "Administrator",
			Privilege:      "Administrator",
			Comment:        utils.StringPtr("Built-in account for admin"),
			LoginFailures:  0,
			LoginSuccesses: 15,
			LocalGroups:    []string{"Administrators"},
			GlobalGroups:   []string{},
		},
	}
}
