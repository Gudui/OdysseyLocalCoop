#include "lib.hpp"
#include "nn/fs/fs_files.hpp"

#include "program/config.hpp"
#include "program/loggers.hpp"

#include <cstddef>

namespace ocoop::config {
namespace {

constexpr const char* kConfigPath = "content:/OCoop/settings.ini";
constexpr size_t kConfigMaxBytes = 4096;
constexpr unsigned kGameTicksPerSecond = 60;

Settings sSettings = {
    1.12f, 1.65f, 500.0f, 2500.0f, 0.05f,
    "MarioColorLuigi", "MarioColorLuigi",
    10.0f,
    3000.0f, 1.5f, 10.0f, true,
    true, 10, -560.0f, 260.0f, -64.0f,
    true, 3, 0.0f, 0.0f,
};

Settings Defaults() {
    return Settings{
        1.12f, 1.65f, 500.0f, 2500.0f, 0.05f,
        "MarioColorLuigi", "MarioColorLuigi",
        10.0f,
        3000.0f, 1.5f, 10.0f, true,
        true, 10, -560.0f, 260.0f, -64.0f,
        true, 3, 0.0f, 0.0f,
    };
}

float Clamp(float value, float minValue, float maxValue) {
    if (value < minValue)
        return minValue;
    if (value > maxValue)
        return maxValue;
    return value;
}

const char* SkipSpaces(const char* p, const char* end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r'))
        ++p;
    return p;
}

const char* TrimSpacesEnd(const char* begin, const char* end) {
    while (end > begin &&
           (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
        --end;
    return end;
}

bool KeyEquals(const char* begin, const char* end, const char* key) {
    while (begin < end && *key) {
        if (*begin != *key)
            return false;
        ++begin;
        ++key;
    }
    return begin == end && *key == '\0';
}

bool IsDigit(char c) {
    return c >= '0' && c <= '9';
}

bool ParseFloat(const char* begin, const char* end, float* outValue) {
    const char* p = SkipSpaces(begin, end);
    bool negative = false;
    if (p < end && (*p == '-' || *p == '+')) {
        negative = *p == '-';
        ++p;
    }

    bool sawDigit = false;
    float value = 0.0f;
    while (p < end && IsDigit(*p)) {
        sawDigit = true;
        value = value * 10.0f + static_cast<float>(*p - '0');
        ++p;
    }

    if (p < end && *p == '.') {
        ++p;
        float scale = 0.1f;
        while (p < end && IsDigit(*p)) {
            sawDigit = true;
            value += static_cast<float>(*p - '0') * scale;
            scale *= 0.1f;
            ++p;
        }
    }

    if (!sawDigit)
        return false;
    *outValue = negative ? -value : value;
    return true;
}

void CopyString(char* destination, size_t capacity,
                const char* begin, const char* end) {
    begin = SkipSpaces(begin, end);
    end = TrimSpacesEnd(begin, end);
    size_t length = static_cast<size_t>(end - begin);
    if (length >= capacity)
        length = capacity - 1;
    for (size_t i = 0; i < length; ++i)
        destination[i] = begin[i];
    destination[length] = '\0';
}

void ParseConfigText(const char* text, size_t length, Settings* settings) {
    const char* p = text;
    const char* end = text + length;
    while (p < end) {
        const char* lineBegin = p;
        while (p < end && *p != '\n')
            ++p;
        const char* lineEnd = p;
        if (p < end)
            ++p;

        const char* cur = SkipSpaces(lineBegin, lineEnd);
        if (cur >= lineEnd || *cur == '#' || *cur == ';')
            continue;

        const char* equals = cur;
        while (equals < lineEnd && *equals != '=')
            ++equals;
        if (equals >= lineEnd)
            continue;

        const char* keyEnd = TrimSpacesEnd(cur, equals);
        const char* valueBegin = equals + 1;
        float value = 0.0f;

        if (KeyEquals(cur, keyEnd, "player.p2.body")) {
            CopyString(settings->p2Body, sizeof(settings->p2Body), valueBegin, lineEnd);
        } else if (KeyEquals(cur, keyEnd, "player.p2.cap")) {
            CopyString(settings->p2Cap, sizeof(settings->p2Cap), valueBegin, lineEnd);
        } else if (!ParseFloat(valueBegin, lineEnd, &value)) {
            continue;
        } else if (KeyEquals(cur, keyEnd, "camera.zoom.base")) {
            settings->cameraBaseZoom = value;
        } else if (KeyEquals(cur, keyEnd, "camera.zoom.max")) {
            settings->cameraMaxZoom = value;
        } else if (KeyEquals(cur, keyEnd, "camera.zoom.separation_start")) {
            settings->cameraSeparationStart = value;
        } else if (KeyEquals(cur, keyEnd, "camera.zoom.separation_full")) {
            settings->cameraSeparationFull = value;
        } else if (KeyEquals(cur, keyEnd, "camera.zoom.lerp")) {
            settings->cameraLerp = value;
        } else if (KeyEquals(cur, keyEnd, "respawn.delay_seconds")) {
            settings->respawnDelaySeconds = value;
        } else if (KeyEquals(cur, keyEnd, "bubble.distance")) {
            settings->bubbleDistance = value;
        } else if (KeyEquals(cur, keyEnd, "bubble.hold_seconds")) {
            settings->bubbleHoldSeconds = value;
        } else if (KeyEquals(cur, keyEnd, "bubble.cooldown_seconds")) {
            settings->bubbleCooldownSeconds = value;
        } else if (KeyEquals(cur, keyEnd, "bubble.water_counts_as_ground")) {
            settings->bubbleWaterCountsAsGround = value != 0.0f;
        } else if (KeyEquals(cur, keyEnd, "competition.coin.enabled")) {
            settings->coinRaceEnabled = value != 0.0f;
        } else if (KeyEquals(cur, keyEnd, "competition.coin.target")) {
            settings->coinRaceTarget = static_cast<int>(value);
        } else if (KeyEquals(cur, keyEnd, "competition.coin.hud_x")) {
            settings->coinRaceHudX = value;
        } else if (KeyEquals(cur, keyEnd, "competition.coin.hud_y")) {
            settings->coinRaceHudY = value;
        } else if (KeyEquals(cur, keyEnd, "competition.coin.hud_spacing")) {
            settings->coinRaceHudSpacing = value;
        } else if (KeyEquals(cur, keyEnd, "competition.moon.enabled")) {
            settings->moonRaceEnabled = value != 0.0f;
        } else if (KeyEquals(cur, keyEnd, "competition.moon.target")) {
            settings->moonRaceTarget = static_cast<int>(value);
        } else if (KeyEquals(cur, keyEnd, "competition.hud_x")) {
            settings->competitionHudX = value;
        } else if (KeyEquals(cur, keyEnd, "competition.hud_y")) {
            settings->competitionHudY = value;
        }
    }
}

void Apply(Settings settings) {
    settings.cameraBaseZoom = Clamp(settings.cameraBaseZoom, 1.0f, 3.5f);
    settings.cameraMaxZoom = Clamp(settings.cameraMaxZoom,
                                   settings.cameraBaseZoom, 3.5f);
    settings.cameraSeparationStart = Clamp(settings.cameraSeparationStart,
                                           0.0f, 19999.0f);
    settings.cameraSeparationFull = Clamp(settings.cameraSeparationFull,
                                          settings.cameraSeparationStart + 1.0f,
                                          20000.0f);
    settings.cameraLerp = Clamp(settings.cameraLerp, 0.001f, 1.0f);
    settings.respawnDelaySeconds = Clamp(settings.respawnDelaySeconds, 0.0f, 60.0f);
    settings.bubbleDistance = Clamp(settings.bubbleDistance, 100.0f, 20000.0f);
    settings.bubbleHoldSeconds = Clamp(settings.bubbleHoldSeconds, 0.0f, 10.0f);
    settings.bubbleCooldownSeconds = Clamp(settings.bubbleCooldownSeconds, 0.0f, 60.0f);
    if (settings.coinRaceTarget < 1)
        settings.coinRaceTarget = 1;
    if (settings.coinRaceTarget > 999)
        settings.coinRaceTarget = 999;
    settings.coinRaceHudX = Clamp(settings.coinRaceHudX, -2000.0f, 2000.0f);
    settings.coinRaceHudY = Clamp(settings.coinRaceHudY, -1200.0f, 1200.0f);
    settings.coinRaceHudSpacing = Clamp(settings.coinRaceHudSpacing, -500.0f, 500.0f);
    if (settings.moonRaceTarget < 1)
        settings.moonRaceTarget = 1;
    if (settings.moonRaceTarget > 999)
        settings.moonRaceTarget = 999;
    settings.competitionHudX = Clamp(settings.competitionHudX, -500.0f, 500.0f);
    settings.competitionHudY = Clamp(settings.competitionHudY, -300.0f, 300.0f);
    sSettings = settings;
}

unsigned SecondsToFrames(float seconds) {
    return static_cast<unsigned>(seconds * static_cast<float>(kGameTicksPerSecond) + 0.5f);
}

void LogSettings(const char* state) {
    Logging.Log("[OCoop] CONFIG-0001 %s camera base=%.2f max=%.2f start=%.0f full=%.0f lerp=%.3f",
                state, sSettings.cameraBaseZoom, sSettings.cameraMaxZoom,
                sSettings.cameraSeparationStart, sSettings.cameraSeparationFull,
                sSettings.cameraLerp);
    Logging.Log("[OCoop] CONFIG-0001 %s p2 body=\"%s\" cap=\"%s\" respawn=%.2fs",
                state, sSettings.p2Body, sSettings.p2Cap,
                sSettings.respawnDelaySeconds);
    Logging.Log("[OCoop] CONFIG-0001 %s bubble distance=%.0f hold=%.2fs cooldown=%.2fs water-ground=%d path=%s",
                state, sSettings.bubbleDistance, sSettings.bubbleHoldSeconds,
                sSettings.bubbleCooldownSeconds,
                sSettings.bubbleWaterCountsAsGround ? 1 : 0, kConfigPath);
    Logging.Log("[OCoop] CONFIG-0001 %s competition coin=%d/%d moon=%d/%d panel=(%.0f,%.0f)",
                state, sSettings.coinRaceEnabled ? 1 : 0, sSettings.coinRaceTarget,
                sSettings.moonRaceEnabled ? 1 : 0, sSettings.moonRaceTarget,
                sSettings.competitionHudX, sSettings.competitionHudY);
}

}  // namespace

const Settings& Get() {
    return sSettings;
}

void Reload() {
    Settings settings = Defaults();
    nn::fs::FileHandle handle = {};
    Result result = nn::fs::OpenFile(&handle, kConfigPath, nn::fs::OpenMode_Read);
    if (result != 0) {
        Apply(settings);
        LogSettings("defaults (open failed)");
        return;
    }

    long fileSize = 0;
    result = nn::fs::GetFileSize(&fileSize, handle);
    if (result != 0 || fileSize <= 0) {
        nn::fs::CloseFile(handle);
        Apply(settings);
        LogSettings("defaults (unreadable)");
        return;
    }

    char buffer[kConfigMaxBytes + 1] = {};
    size_t readSize = static_cast<size_t>(fileSize);
    if (readSize > kConfigMaxBytes)
        readSize = kConfigMaxBytes;
    result = nn::fs::ReadFile(handle, 0, buffer, static_cast<ulong>(readSize));
    nn::fs::CloseFile(handle);
    if (result != 0) {
        Apply(settings);
        LogSettings("defaults (read failed)");
        return;
    }

    buffer[readSize] = '\0';
    ParseConfigText(buffer, readSize, &settings);
    Apply(settings);
    LogSettings("loaded");
}

unsigned RespawnDelayFrames() {
    return SecondsToFrames(sSettings.respawnDelaySeconds);
}

unsigned BubbleHoldFrames() {
    return SecondsToFrames(sSettings.bubbleHoldSeconds);
}

unsigned BubbleCooldownFrames() {
    return SecondsToFrames(sSettings.bubbleCooldownSeconds);
}

}  // namespace ocoop::config
