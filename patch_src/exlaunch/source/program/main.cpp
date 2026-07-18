#include "lib.hpp"
#include "lib/patch/patcher_impl.hpp"

#include "program/config.hpp"
#include "program/diagnostics.hpp"
#include "program/diagnostics_profile.hpp"
#include "program/loggers.hpp"

#include "nn/fs/fs_files.hpp"

#include <cstddef>
#include <cstdint>
#include <new>

/*
 * OCoopMod — local co-op for Super Mario Odyssey 1.0.0 (0100000000010000).
 *
 * Milestone 1 (AGENTS.md): two PlayerActorHakoniwa instances in one
 * StageScene, each bound to its own controller port.
 */

/* NSO .text offsets for Odyssey 1.0.0, from OdysseyDecomp data/file_list.yml.
 * Ghidra VA = NSO offset + 0x7100000000. */
namespace PatchOffsets {
    /* PATCH-0024: exact change-world scene boundary. file_list.yml identifies
     * DemoChangeWorldScene::exeTalk at 0x4a7070. Ghidra run
     * 20260717-093857 proves the entry instruction is
     * `stp x20,x19,[sp,#-0x20]!`, so it is safe for an inline hook. */
    constexpr ptrdiff_t DemoChangeWorldSceneExeTalk = 0x4a7070;

    /* StageScene */
    constexpr ptrdiff_t StageSceneInit = 0x4c861c;                    // StageScene::init — player creation happens in here

     
    constexpr ptrdiff_t SceneInitPlayerCountInsn = 0x4c89f0;          // mov w4,#0x4 — already >= 2, no patch required
    constexpr ptrdiff_t SceneInitLiveActorKitCall = 0x4c8a04;         // bl initLiveActorKitWithGraphics inside StageScene::init

     
    constexpr ptrdiff_t PlayerActorHakoniwaCtorC2 = 0x41b168;         // base-object ctor(const char*)
    constexpr ptrdiff_t PlayerActorHakoniwaCtorC1 = 0x41b250;         // complete-object ctor — what the factory calls
    constexpr ptrdiff_t PlayerActorHakoniwaInitPlayer = 0x41b334;     
    constexpr ptrdiff_t CreatePlayerFunctionHakoniwa = 0x4b5dc8;      // PlayerActorBase* createPlayerFunction<PlayerActorHakoniwa>(const char*) — new(0x508)+C1
    constexpr ptrdiff_t RsInitPlayerActorInfo = 0x56f1c4;             // rs::initPlayerActorInfo(PlayerActorBase*, const PlayerInitInfo&) — copies +0x08→actor+0x110 (viewMtx), +0x10→actor+0x118 (portNo), pose from +0x28/+0x34
    constexpr ptrdiff_t AlCreatePadRumbleKeeper = 0x86b710;           // al::createPadRumbleKeeper(const al::LiveActor*, s32 port)

     
    constexpr ptrdiff_t P1InitPlayerVCall = 0x4c9fa4;                 // blr vtable+0xe0: x0=P1, x1=&ActorInitInfo(sp+0x108), x2=&PlayerInitInfo(sp+0x508) — capture here (runtime-confirmed 2026-07-07)
    constexpr ptrdiff_t P1RegisterPlayerCall = 0x4c9fd4;              // bl alPlayerFunction::registerPlayer(P1, keeper)
    constexpr ptrdiff_t P1PostRegisterInsn = 0x4c9fd8;                

     
    constexpr ptrdiff_t AlGetPlayerControllerPort = 0x85bfec;         // al::getPlayerControllerPort(s32 npadOrder) — Matching; returns -1 if that Npad doesn't exist
    constexpr ptrdiff_t AlGetMainControllerPort = 0x85bfb0;           // al::getMainControllerPort() = getPlayerControllerPort(0) — Matching
    constexpr ptrdiff_t AlIsPadConnected = 0x863340;                  // al::isPadConnected(s32 port) — NO bounds check: caller must ensure port >= 0
    constexpr ptrdiff_t AlGetDisplayName = 0x99eb28;                  // al::getDisplayName(const char** out, const al::ActorInitInfo&) — Matching; what StageScene::init used for P1's name

     
    constexpr ptrdiff_t GameDataHolderSetSeparatePlay = 0x531678;     // GameDataHolder::setSeparatePlay(bool) — Matching
    constexpr ptrdiff_t RsIsSeparatePlay = 0x575af4;                  // rs::isSeparatePlay(const al::IUseSceneObjHolder*)
    constexpr ptrdiff_t RsChangeSeparatePlayMode = 0x575b18;          // rs::changeSeparatePlayMode()
    constexpr ptrdiff_t IsSeparatePlaySingleJoy = 0x44fe3c;           // PlayerInputFunction::isSeparatePlaySingleJoy(const al::LiveActor*, s32)
    /* Input aggregation root cause (Ghidra run 20260709-202240, PATCH-0005):
     * changeSinglePlayMode sets NpadController[port(0)]+0x178 = -1 = "index
     * controller mode -1" = the FIRST Npad controller aggregates input from ANY
     * physical pad (vanilla any-controller-drives-Mario). That is exactly the
     * observed one-way bleed: P2's pad also drives P1; P1's pad does not drive
     * P2. changeMultiPlayMode(gps, players, n) loops i=0..players-1 calling
     * al::NpadController::setIndexControllerMode(controller[port(i)], i) —
     * pinning pad i to player i. Native 2P (connectControllerSeparatePlay
     * 0x5775d0) calls changeMultiPlayMode(gps,2,2) on applet success. We call
     * ONLY that — NOT rs::changeSeparatePlayMode 0x575b18, which additionally
     * sets GameDataHolder+0x245 (isSeparatePlay) and would reroute Mario's CAP
     * to port(1) (P2's pad would drive Cappy — worse bleed). */
    constexpr ptrdiff_t GamePadSystemChangeMultiPlayMode = 0x85a548;  // al::GamePadSystem::changeMultiPlayMode(int players, int n) — Eii, verified vs file_list + Ghidra
    constexpr ptrdiff_t GamePadSystemChangeSinglePlayMode = 0x85a27c; // al::GamePadSystem::changeSinglePlayMode() — sets first Npad to aggregate mode (-1)
    constexpr ptrdiff_t ConnectControllerSeparatePlay = 0x5775d0;     // ControllerAppletFunction::connectControllerSeparatePlay(al::GamePadSystem*) — native 2P recipe (reference)
    constexpr ptrdiff_t PlayerInputGetSeparatePlay1P = 0x44cf14;      // PlayerInput::getSeparatePlay1P() = getPlayerControllerPort(0) — dynamic, NOT "port 0"
    constexpr ptrdiff_t PlayerInputGetSeparatePlay2P = 0x44c3b4;      // PlayerInput::getSeparatePlay2P() = getPlayerControllerPort(1) — dynamic, NOT "port 1"
    constexpr ptrdiff_t PlayerFunctionGetPlayerInputPort = 0x447da0;  // PlayerFunction::getPlayerInputPort(const al::LiveActor*) — tail-call actor vtable+0xe8 getPortNo

    /* al engine — all verified against file_list.yml; the values the AGENTS.md
     * draft table carried for this cluster (0x71e0xx / 0x725bac) were fabricated. */
    constexpr ptrdiff_t SceneInitLiveActorKit = 0x9ce73c;             // al::Scene::initLiveActorKit(const SceneInitInfo&, s32 maxActors, s32 maxPlayers, s32 maxCameras) — Matching
    constexpr ptrdiff_t SceneInitLiveActorKitImpl = 0x9ce824;         // al::Scene::initLiveActorKitImpl(...) — Matching
    constexpr ptrdiff_t SceneInitLiveActorKitWithGraphics = 0x9ce8c0; // al::Scene::initLiveActorKitWithGraphics(const GraphicsInitArg&, const SceneInitInfo&, s32, s32, s32) — Matching
    constexpr ptrdiff_t PlayerHolderRegisterPlayer = 0x9a3db4;        // al::PlayerHolder::registerPlayer(al::LiveActor*, al::PadRumbleKeeper*)
    constexpr ptrdiff_t AlPlayerFunctionRegisterPlayer = 0x9a4fe4;    // alPlayerFunction::registerPlayer(al::LiveActor*, al::PadRumbleKeeper*)

     
    constexpr ptrdiff_t RecoveryIsEnableRecovery = 0x460cfc;          // PlayerRecoverySafetyPoint::isEnableRecovery() const -> bool (gate; mActor at this+0x00, no vtable, sizeof 0xb8)
    constexpr ptrdiff_t RecoveryIsValid = 0x460c90;                   // PlayerRecoverySafetyPoint::isValid() const = isEnableRecovery() && hasSafety
    constexpr ptrdiff_t PreMovementRecoveryIsValidReturn = 0x41feb8; // LR after BL isValid at 0x41feb4 in PlayerActorHakoniwa::executePreMovementNerveChange; Ghidra 20260715-072109
    constexpr ptrdiff_t RecoverySetSafetyPoint = 0x460508;            // PlayerRecoverySafetyPoint::setSafetyPoint(pos, normal, areaObj) — destination override (float-to-partner lever)
    constexpr ptrdiff_t RecoveryStartRecovery = 0x460f0c;             // PlayerRecoverySafetyPoint::startRecovery(f32) — spawns/animates the TractorBubble; destination read later, so override the safety point here
    constexpr ptrdiff_t RecoveryGetSafetyPoint = 0x460d48;            // PlayerRecoverySafetyPoint::getSafetyPoint() const -> const Vector3f& (returns mDefaultSafetyPos if set!)
    constexpr ptrdiff_t PlayerStateAbyssAppear = 0x466b54;            // PlayerStateAbyss::appear() — abyss-fall trigger; reads isValid() to pick Recovery(bubble) vs Fall(death)
    constexpr ptrdiff_t RecoveryDeadExeRecovery = 0x479884;           // PlayerStateRecoveryDead::exeRecovery() — reads getSafetyPoint at first step, hard-places at it at the end; state+0x18=actor, state+0x20=PlayerRecoverySafetyPoint* (Ghidra 20260709-221256)
    constexpr ptrdiff_t RecoveryDeadExeFall = 0x47a25c;               // PlayerStateRecoveryDead::exeFall() — ends the state ONLY via vtable+0x28 when rs::isOnGround; file_list.yml + Ghidra 20260714-180854
    constexpr ptrdiff_t AlSetTrans = 0x8ee364;                        // al::setTrans(al::LiveActor*, const sead::Vector3f&) — file_list.yml
    constexpr ptrdiff_t AlIsGreaterEqualStep = 0x959c24;              // al::isGreaterEqualStep(const al::IUseNerve*, int) — file_list.yml; exeRecovery itself calls it on the state
    constexpr ptrdiff_t DimensionKeeperValidate = 0x54168c;           // ActorDimensionKeeper::validate() — file_list.yml + Matching decomp (sets mIsValid; control's driver 0x420b58 never validates, only invalidates)

    /* Partner lookup + pose helpers (all Matching, verified vs file_list.yml). */
    constexpr ptrdiff_t AlGetPlayerActor = 0x9a3f70;                  // al::getPlayerActor(const al::LiveActor*, s32) -> al::LiveActor* (walks actor->getSceneInfo()->playerHolder; live, no caching)
    constexpr ptrdiff_t AlGetTrans = 0x8ee66c;                        // al::getTrans(const al::LiveActor*) -> const sead::Vector3f& (returns &vec3 in x0)
    constexpr ptrdiff_t AlGetGravity = 0x8ee64c;                      // al::getGravity(const al::LiveActor*) -> const sead::Vector3f&
    constexpr ptrdiff_t CameraPoserFollowLimitCalcDistanceRaw = 0x0c8b9c; // CameraPoserFollowLimit::calcDistanceRaw() const; Ghidra 20260709-215339, direct distance producer
    constexpr ptrdiff_t CameraPoserFollowLimitCalcCameraPose = 0x0caa60; // CameraPoserFollowLimit::calcCameraPose(sead::LookAtCamera*) const; Ghidra 20260709-224232, final LookAtCamera output consumer

     
    constexpr ptrdiff_t ActorCameraTargetCalcTrans = 0x971fd8;        // al::ActorCameraTarget::calcTrans(sead::Vector3f* out) const — Matching; out = trackedActor world pos + offsets

     
    constexpr ptrdiff_t PlayerCameraCalcCameraMoveInput = 0x57309c;   // PlayerCameraFunction::calcCameraMoveInput(sead::Vector2f*, const al::LiveActor*) - file_list.yml (size 92) + Ghidra 20260717-223949
    constexpr ptrdiff_t AlTryGetPlayerActor = 0x9a3fe4;               // al::tryGetPlayerActor(const al::LiveActor*, s32) - file_list.yml; bounds-checked, returns nullptr (Ghidra 20260717-223949)
    constexpr ptrdiff_t PlayerInputGetStickCameraRaw = 0x44def4;      // PlayerInput::getStickCameraRaw() const -> const sead::Vector2f& - file_list.yml; honours input-disabled flag +0x98

     
    constexpr ptrdiff_t PlayerHakoniwaControl = 0x420630;             // PlayerActorHakoniwa::control() — per-frame per-player hook site (file_list.yml)
    constexpr ptrdiff_t PlayerForceRecoveryHelper = 0x4273f4;         // unnamed(player, hackCap, carryKeeper, bindKeeper, equipUser, stateAbyss) — prepareRecovery + setNerve(NrvAbyss); no HP cost
    constexpr ptrdiff_t NrvPlayerActorHakoniwaAbyss = 0x1d789f0;      // .data Nerve object passed to al::setNerve by checkDeathArea + 0x4273f4 (Ghidra decomp)
    constexpr ptrdiff_t PlayerFunctionIsPlayerDeadStatus = 0x447c18;  // PlayerFunction::isPlayerDeadStatus(const al::LiveActor*) — file_list.yml
    constexpr ptrdiff_t PlayerStateDamageLifeExeDead = 0x469e10;     // PlayerStateDamageLife::exeDead() — file_list.yml + Ghidra 20260710-235537
    constexpr ptrdiff_t PlayerAnimatorIsAnimEnd = 0x42a630;          // PlayerAnimator::isAnimEnd() const — file_list.yml
    constexpr ptrdiff_t AlIsNerve = 0x959c58;                         // al::isNerve(const al::IUseNerve*, const al::Nerve*) — file_list.yml; checkDeathArea passes the player actor directly
    constexpr ptrdiff_t AlIsClipped = 0x8d79d0;                       // al::isClipped(const al::LiveActor*) — 12-byte flag getter; logged to evaluate as v2 "out of view" selector
     
    constexpr ptrdiff_t PlayerDamageKeeperDamage = 0x43f154;         // PlayerDamageKeeper::damage(s32)
    constexpr ptrdiff_t PlayerDamageKeeperDamageForce = 0x43f304;    // PlayerDamageKeeper::damageForce(s32)
    constexpr ptrdiff_t PlayerDamageKeeperDead = 0x43f390;           // PlayerDamageKeeper::dead()
    constexpr ptrdiff_t GameDataHolderAccessorCtor = 0x5316ec;      // GameDataHolderAccessor::C2(const al::IUseSceneObjHolder*)
    constexpr ptrdiff_t GameDataGetPlayerHitPoint = 0x528678;        // GameDataFunction::getPlayerHitPoint(GameDataHolderAccessor)
    constexpr ptrdiff_t GameDataGetPlayerHitPointMaxCurrent = 0x528690; // GameDataFunction::getPlayerHitPointMaxCurrent(GameDataHolderAccessor)
    constexpr ptrdiff_t GameDataRecoveryPlayerMax = 0x528780;        
    constexpr ptrdiff_t GameDataRecoveryPlayerMaxForSystem = 0x5287e0; // GameDataFunction::recoveryPlayerMaxForSystem(const GameDataHolder*)
    constexpr ptrdiff_t GameDataGetLifeMaxUpItem = 0x528630;         // GameDataFunction::getLifeMaxUpItem(const al::LiveActor*) — sole semantic max-up acquisition funnel; file_list.yml + Ghidra 20260712-213429
    constexpr ptrdiff_t StageSceneStateMissCheckMiss = 0x4e3594;     // StageSceneStateMiss::checkMiss() const — sole global miss selector; Ghidra 20260712-211024

     
    constexpr ptrdiff_t StageSceneLayoutCtor = 0x20c570;
    constexpr ptrdiff_t StageSceneLayoutStart = 0x20ca20;
    constexpr ptrdiff_t StageSceneLayoutEnd = 0x20ccb8;
    constexpr ptrdiff_t StageSceneLayoutEndWithoutCoin = 0x20cc58;    
    constexpr ptrdiff_t CounterLifeCtor = 0x1e53c4;
    constexpr ptrdiff_t CounterLifeAppear = 0x1e5504;
    constexpr ptrdiff_t CounterLifeKill = 0x1e5530;
    constexpr ptrdiff_t CounterLifeSetCount = 0x1e5734;
    constexpr ptrdiff_t CounterLifeStart = 0x1e5750;
    constexpr ptrdiff_t CompassAppear = 0x1e3c9c;       
    constexpr ptrdiff_t CompassEnd = 0x1e3e78;          
    constexpr ptrdiff_t AlIsActiveLayout = 0x8b1ef8;                  // al::isActive(const al::LayoutActor*) — file_list.yml; 8-byte flag read
    constexpr ptrdiff_t CounterLifeEnd = 0x1e57dc;      
    constexpr ptrdiff_t AlLayoutActorKill = 0x8b1acc;   
    constexpr ptrdiff_t RsIsActiveDemoActor = 0x5508d4;  // _ZN2rs12isActiveDemoEPKN2al9LiveActorE — file_list.yml (24 B leaf); PATCH-0014 v8 demo-end restore gate
    /* PATCH-0019 native coin-score HUD. StageSceneLayout C1 allocates every
     * CoinCounter as 0x150 bytes (Ghidra run 20260715-184705). Matching C1
     * proves mIsUpdateCount at +0x14c; clearing it prevents these duplicate
     * counters from polling the shared GameData economy. */
    constexpr ptrdiff_t CoinCounterCtor = 0x1de5a8;
    constexpr ptrdiff_t CoinCounterUpdatePanel = 0x1de4f8;
    constexpr ptrdiff_t CoinCounterKill = 0x1de73c;
    constexpr ptrdiff_t CoinCounterTryStart = 0x1de774;
    /* PATCH-0019 combined competition HUD. Ghidra run
     * 20260715-202346 proves LayoutActor is 0x130 bytes, its IUseLayout and
     * IUseSceneObjHolder subobjects are +0x08/+0x38, initLayoutActor resolves
     * LayoutData/<name>, and base appear/kill only toggle the actor lifecycle.
     * The GameData getters below are Matching/file_list.yml and receive the
     * one-pointer GameDataHolderAccessor value produced from layout+0x38. */
    constexpr ptrdiff_t LayoutActorCtor = 0x8b1924;
    constexpr ptrdiff_t LayoutActorAppear = 0x8b1a78;
    constexpr ptrdiff_t LayoutActorInit = 0x8b51c4;
    constexpr ptrdiff_t LayoutShowPane = 0x8b2a24;
    constexpr ptrdiff_t LayoutHidePane = 0x8b2a68;
    constexpr ptrdiff_t ShineCounterKill = 0x202b10;
    constexpr ptrdiff_t GameDataGetCoinCollectNum = 0x529b50;
    constexpr ptrdiff_t GameDataGetCoinCollectNumMax = 0x529b68;
    constexpr ptrdiff_t GameDataGetCoinNum = 0x529c24;
    constexpr ptrdiff_t GameDataGetTotalShineNum = 0x528a64;
    /* PATCH-0026: Matching GameDataFunction::getGotShineNum at 0x528974
     * calls GameDataFile::getShineNum() for file_id -1. Ghidra run
     * 20260718-142945 proves that no-argument getter reads currentWorldId at
     * GameDataFile+0x9f0 and indexes mShineNum at +0x858. Unlike
     * getTotalShineNum, this is the current-kingdom collected count. */
    constexpr ptrdiff_t GameDataGetGotShineNum = 0x528974;
    /* PATCH-0020 persistence keys. file_list.yml + Ghidra runs
     * 20260716-093941/-094248/-094343 prove these Matching accessors read the
     * active GameDataFile's stable save-data ID (+0x478) and current world ID
     * (+0x9f0). Normal saves copy the stable ID into the write field; only a
     * save-slot copy generates a new write ID. */
    constexpr ptrdiff_t GameDataGetSaveDataIdForPrepo = 0x527a30;
    constexpr ptrdiff_t GameDataGetCurrentWorldId = 0x528358;
    /* PATCH-0023 save:/ serialization gate. Matching decomp source proves
     * isDoneSaveDataSequence returns true only after the shared native
     * SaveDataDirector has no running sequence. OCoop journal writes execute
     * synchronously on the main thread, so an idle result prevents a native
     * save request from starting until the journal handle is closed. */
    constexpr ptrdiff_t AlIsDoneSaveDataSequence = 0x9cdb28;
     
    constexpr ptrdiff_t ShineReceiveMsg = 0x1cfb68;
    constexpr ptrdiff_t ShineIsGot = 0x1d06a8;       // Shine::isGot() const; file_list.yml + Ghidra 20260716-103146, native GameData lookup by shine+0x290 index
    constexpr ptrdiff_t RsIsMsgShineGet = 0x58f20c;
    constexpr ptrdiff_t RsIsMsgShineGet2D = 0x58f294;
     
    constexpr ptrdiff_t ShineTowerTryLevelUp = 0x30e0f8;

    /* Capture-aware bubble (Ghidra run 20260713-155149): cancelHackArea is the
     * game's own no-hack-area eject — sends CancelHackArea to the creature's
     * sensor (keeper+0x70) from the player's body sensor (keeper+0x50), falls
     * back to CancelHack + a hit reaction. Sole BL caller is
     * PlayerActorHakoniwa::exeHack, i.e. it is designed to run from the hacked
     * player's own per-frame context — exactly our control() hook. */
    constexpr ptrdiff_t PlayerHackKeeperCancelHackArea = 0x4496bc;    // PlayerHackKeeper::cancelHackArea() — file_list.yml + decompile
    constexpr ptrdiff_t LayoutGetActionFrameMax = 0x8b0ce0;
    constexpr ptrdiff_t LayoutSetPaneLocalTrans2 = 0x8b264c;
    constexpr ptrdiff_t LayoutSetPaneString = 0x8b3820;
    constexpr ptrdiff_t DamageForceTagPreMove = 0x41ffd0;
    constexpr ptrdiff_t DamageForceTagDeathArea = 0x4273bc;
    constexpr ptrdiff_t DamageForceTagCollisionA = 0x42976c;
    constexpr ptrdiff_t DamageForceTagCollisionB = 0x429794;
    constexpr ptrdiff_t DamageForceTagCollisionC = 0x4297b4;

     
    constexpr ptrdiff_t DoorWarpStageChangeReceiveMsg = 0x2629f4;     // DoorWarpStageChange::receiveMsg(SensorMsg*, other, self) — file_list.yml
    constexpr ptrdiff_t DoorWarpReceiveMsg = 0x260bd4;                // DoorWarp::receiveMsg — same gate shape, controller also at +0x108
    constexpr ptrdiff_t AlIsMsgBindStart = 0x8f965c;                  // al::isMsgBindStart(const al::SensorMsg*) — file_list.yml
    constexpr ptrdiff_t AlIsMsgBindInit = 0x8f96e4;                   // al::isMsgBindInit(const al::SensorMsg*) — file_list.yml
    constexpr ptrdiff_t AlGetSensorHost = 0x8f1ec0;                   // al::getSensorHost(const al::HitSensor*) -> LiveActor* — file_list.yml
    constexpr ptrdiff_t AlIsSensorPlayer = 0x8fda50;                  // al::isSensorPlayer(const al::HitSensor*) — file_list.yml
    constexpr ptrdiff_t RsIsPlayerOnGround = 0x571224;                // rs::isPlayerOnGround(const al::LiveActor*) — file_list.yml

     
    constexpr ptrdiff_t AlSendMsgPlayerItemGet = 0x8f3b74;
    constexpr ptrdiff_t CoinExeCountUp = 0x1bc624;                   // Coin::exeCountUp(); Matching + Ghidra entry listing 20260715-194350
    constexpr ptrdiff_t Coin2DReceiveMsg = 0x1bd348;
    constexpr ptrdiff_t RsIsMsgItemGet2D = 0x58efec;
    constexpr ptrdiff_t GameDataAddCoin = 0x529c10;                  // GameDataFunction::addCoin(GameDataHolderWriter, s32); file_list.yml + Ghidra 20260715-193359
    constexpr ptrdiff_t ProjectItemDirectorAppearItem = 0x4c0094;    // ProjectItemDirector::appearItem(..., const al::HitSensor*); file_list.yml + Ghidra 20260718-180615
    constexpr ptrdiff_t BlockQuestion2DReceiveMsg = 0x21eff0;        // BlockQuestion2D::receiveMsg(...); Matching source + file_list.yml
    constexpr ptrdiff_t BlockTransparent2DReceiveMsg = 0x220ff0;     // BlockTransparent2D::receiveMsg(...); file_list.yml + Ghidra 20260718-204409/204706
    constexpr ptrdiff_t BlockBrick2DReceiveMsg = 0x21c518;           // BlockBrick2D::receiveMsg(...); file_list.yml + Ghidra 20260718-211707 (single-item state attacker provenance)
    constexpr ptrdiff_t RsIsMsgPlayerUpperPunch2D = 0x589e64;       // rs::isMsgPlayerUpperPunch2D(const al::SensorMsg*); Matching source + file_list.yml
    constexpr ptrdiff_t RsIsMsgPlayerObjUpperPunch2D = 0x589eec;    // rs::isMsgPlayerObjUpperPunch2D(const al::SensorMsg*); Matching source + file_list.yml
    constexpr ptrdiff_t RsSendPlayerCollisionUpperPunchMsg = 0x55b940; // rs::sendPlayerCollisionUpperPunchMsg(...); file_list.yml + Ghidra 20260718-210040/210212
    constexpr ptrdiff_t RsTryGetCollidedCeilingSensor = 0x566154;    // rs::tryGetCollidedCeilingSensor(const IUsePlayerCollision*); file_list.yml

     
    constexpr ptrdiff_t TryChangeNextStageEntry2 = 0x527a48;          // GameDataFunction::tryChangeNextStage entry+4 — file_list.yml 0x527a44 + Ghidra listing 20260711-193754
    constexpr ptrdiff_t GameDataHolderChangeNextStage = 0x52f6f4;     // GameDataHolder::changeNextStage(const ChangeStageInfo*, s32) — file_list.yml; entry insn str x19 (safe)

     
    constexpr ptrdiff_t RsTryChangeNextStage = 0x4d2c54;              // rs::tryChangeNextStage(GameDataHolder*, al::Scene*) — 14 BL callers (StageScene states)
    constexpr ptrdiff_t RsIsInChangeStageArea = 0x544de0;             // rs::isInChangeStageArea(const al::LiveActor*, const sead::Vector3f*) — null pos = use actor trans
    constexpr ptrdiff_t GameDataFindAreaAndChangeNextStage = 0x527c50;// GameDataFunction::findAreaAndChangeNextStage(writer, actor, pos) — builds ChangeStageInfo from the area placement
    constexpr ptrdiff_t AlGetScenePlayerHolder = 0x9cf374;            // al::getScenePlayerHolder(const al::Scene*)
    constexpr ptrdiff_t AlGetPlayerActorFromHolder = 0x9a3f98;        // al::getPlayerActor(const al::PlayerHolder*, s32)

     
    constexpr ptrdiff_t PlayerHakoniwaStartDemoPuppetable = 0x421b84;  // PlayerActorHakoniwa::startDemoPuppetable() — file_list.yml; vcall-only (0 BL callers)
    constexpr ptrdiff_t PlayerHakoniwaEndDemoPuppetable = 0x421e2c;    // PlayerActorHakoniwa::endDemoPuppetable() — file_list.yml; vcall-only (0 BL callers)

    /* PATCH-0013 (cap returns to its owner; Ghidra runs 20260712-104312 /
     * -104354 / -104703, chain re-derived at instruction level in run
     * 20260712-151606 after the v1 crash). rs::getPlayerHeadPos (76 B, full
     * listing):
     *   player = al::getPlayerActor(actor, HARDCODED 0)   // mov w1,wzr @0x56f624
     *   info   = player->vcall(vtable+0x1a8)              // getPlayerInfo() -> PlayerInfo*
     *   if (info && *(info+0x78))                         // ldr x0,[x0,#0x78] @0x56f640
     *       return getHeadPos(*(info+0x78));              // receiver = info->mFormSensorCollisionArranger
     *   else return al::getTrans(actor);                  // mov x0,x19 @0x56f650 — the CAP, not the player
     * PlayerInfo+0x78 = mFormSensorCollisionArranger confirmed by decomp
     * PlayerInfo.h field order (16th pointer; sizeof(PlayerInfo)==0x150).
     * v1 CRASHED by calling getHeadPos ON THE PlayerInfo (it read info+0x00 /
     * info+0x20 as actor/form enums -> wild sensor lookup). Used as the cap
     * RETURN TARGET by HackCap::exeReturn (BL 0x4070a4, per return frame) and
     * HackCap::calcReturnTargetPos (BL 0x4076d8) — so P2's thrown cap flies to
     * and tracks MARIO's head. Entry insns str/stp/add/mov — verified
     * non-PC-relative (run 20260712-104703). 29 BL callers total; the
     * owner-match discriminator (keeper+0x08 == queried actor) limits the
     * redirect to actual HackCaps. */
    constexpr ptrdiff_t RsGetPlayerHeadPos = 0x56f618;                 // rs::getPlayerHeadPos(const al::LiveActor*) -> const sead::Vector3f* — file_list.yml
    constexpr ptrdiff_t ArrangerGetHeadPos = 0x44394c;                 // PlayerFormSensorCollisionArranger::getHeadPos() const — file_list.yml

     
    constexpr ptrdiff_t PlayerHakoniwaStartDemoShineGet = 0x422060;     // PlayerActorHakoniwa::startDemoShineGet() — entry sub sp,sp,#0x40
    constexpr ptrdiff_t PlayerHakoniwaEndDemoShineGet = 0x422194;       // PlayerActorHakoniwa::endDemoShineGet() — entry str x19,[sp,#-0x20]!
    constexpr ptrdiff_t PlayerHakoniwaStartDemoMainShineGet = 0x422218; // PlayerActorHakoniwa::startDemoMainShineGet() — entry str x19,[sp,#-0x20]!
    constexpr ptrdiff_t PlayerHakoniwaEndDemoMainShineGet = 0x422248;   // PlayerActorHakoniwa::endDemoMainShineGet() — entry ldr x8,[x0]
    constexpr ptrdiff_t DemoDirectorRequestShineMainGet = 0x0d5fc8;     // ProjectDemoDirector::requestStartDemoShineMainGet(Shine*, const char*) — entry mov x8,x2
    constexpr ptrdiff_t DemoDirectorRequestShineGrandGet = 0x0d6080;    // ProjectDemoDirector::requestStartDemoShineGrandGet(Shine*, const char*) — entry mov x8,x2

     
    constexpr ptrdiff_t DokanReceiveMsg = 0x2578e4;                     // Dokan::receiveMsg(const SensorMsg*, other, self) — file_list.yml (804 B); entry sub sp,sp,#0x50 (non-PC-relative, listing 20260714-232207)
    /* v2 (2026-07-15): the original six inline hooks AT the helpers'
     * `mov w1,wzr` sites (0x570a24 0x56f724 0x56fa78 0x57228c 0x572340
     * 0x572384) were architectural NO-OPS — exlaunch inline hooks execute the
     * relocated original instruction AFTER the callback (inline_impl.cpp entry:
     * BL impl, then B trampoline holding the original insn), so the mov wiped
     * the redirected index every time. Run 2 proved the consequence: BINDSTART
     * idx=1 arrived and the judge rejected 100% (helpers still judged P1).
     * Replacement: ONE trampoline on al::getPlayerActor itself (entry
     * `str x19,[sp,#-0x20]!`, non-PC-relative, listing 20260715-072157) that
     * rewrites index 0 -> sQueryIdx only inside the receiveMsg scope. */

    /* PATCH-0017 discriminator upgrade (2026-07-15): the first valve run came
     * back all `idx=1 ret=0` with no way to tell WHICH msgs those were. The
     * bind gate only runs for al::isMsgBindStart traffic, and the sender is
     * player-side (PlayerBindKeeper::sendStartMsg 0x42d948, sole BL from
     * PlayerActorHakoniwa::executePreMovementNerveChange 0x41fb34 — no index-0
     * in that chain; Ghidra run 20260715-065050/-065143). Classify the msg in
     * the existing trampoline to separate "BindStart never sent for P2" from
     * "BindStart sent but judge rejects". AlIsMsgBindStart/AlIsMsgBindInit
     * already exist above; only FloorTouch is new (file_list.yml Matching). */
    constexpr ptrdiff_t AlIsMsgPlayerFloorTouch = 0x8f6ea4;             // al::isMsgPlayerFloorTouch(const al::SensorMsg*) — file_list.yml (136 B, Matching)
}

 
#define PATCH_0001_ENABLED 1

/* PATCH-0001b: give P2 a distinct costume so the two players are visually
 * different. Odyssey builds the player model from ObjectData/<name>, where
 * <name> = rs::getInitPlayerModelName(PlayerInitInfo) = the string at
 * PlayerInitInfo+0x18 (body) / +0x20 (cap). The init worker (0x444028) loads
 * that archive ON DEMAND via al::findOrCreateActorResourceWithAnimResource
 * (confirmed in Ghidra, and the exact approach SMOO's initMarioModelPuppet
 * uses), so the costume need NOT be equipped/resident in the save — any romfs
 * ObjectData/<name> works. We only override P2's COPY of the struct; P1 is
 * untouched. Name must be a real 1.0.0 costume archive (see SMOO costumeNames):
 * MarioColorLuigi / MarioColorWario / MarioColorWaluigi are the classic 2P
 * looks; MarioPeach is the unused in-files Peach dress+wig costume (1.0.0
 * ships the archives — "MarioPeach"/"MarioPeachHead" strings present in this
 * binary's rodata per OdysseyDecomp data_strings.csv; SMOO's puppet path uses
 * it as both body and cap name). Set to "" to keep P2 identical to P1. */
#define PATCH_0001_P2_COSTUME_ENABLED 1

 
#define PATCH_0002_ENABLED 1

 
#define PATCH_0003_ENABLED 1
#define PATCH_0003_POP_UP_OFFSET 500.0f

 
#define PATCH_0004_ENABLED 1

 
#define PATCH_0005_ENABLED 1

 
#define PATCH_0007_ENABLED 0
#define PATCH_0007_BASE_ZOOM 1.12f
#define PATCH_0007_MAX_ZOOM  1.65f
#define PATCH_0007_SEP_START 500.0f
#define PATCH_0007_SEP_FULL  2500.0f
#define PATCH_0007_LERP      0.05f

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_001.inc"
#endif

// PATCH-0008: Final camera-pose zoom. The follow-limit raw-distance return
// path (PATCH-0007) is live but does not change the rendered framing. This
// hook instead scales the final LookAtCamera eye-to-target vector after the
// poser has composed its output. The values below are fallback defaults only;
// the user-facing values live in content:/OCoop/settings.ini and are reloaded
// at each StageScene init, so camera tuning does not require a rebuild.
#define PATCH_0008_ENABLED 1

 
#define PATCH_0006_ENABLED 1

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_002.inc"
#endif

 
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_003.inc"
#endif

 
#define PATCH_0011_ENABLED 1

 
#define PATCH_0012_ENABLED 1

 
#define PATCH_0013_ENABLED 1

/* PATCH-0014: independent fixed-corner P2 CounterLife HUD. It receives only
 * PATCH-0009 sidecar-health transitions; the stock P1 CounterLifeCtrl and its
 * GameData-backed HUD remain exactly untouched. */
#define PATCH_0014_ENABLED 1
 
#define PATCH_0014_CAPTURE_RESTORE_ENABLED 0

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_004.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_005.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_006.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_007.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_008.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_009.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_010.inc"
#endif

 
#define PATCH_0009_MOON_HEAL_ENABLED 1

/* PATCH-0009: experimental P2-only health isolation. P1 keeps Odyssey's
 * native GameData health. P2 gets a non-persistent three-heart sidecar. */
#define PATCH_0009_ENABLED 1
#define PATCH_0009_P2_HEALTH_MAX 3

/* PATCH-0016 v2: un-stick cross-dimension bubbles, BOTH directions. exeFall
 * 0x47a25c ends the recovery state ONLY on rs::isOnGround (Ghidra
 * 20260714-180854): a 3D-form player has no ground at a 2D plane, and a
 * 2D-form player (2D-only collision filter) has no ground in the 3D world —
 * both hang in NrvAbyss forever, where control's dimension reconciliation is
 * nerve-gated off. v1 proved force-land works (exit at dist=0, in2D flipped
 * to 1) but the keeper stayed invalid: control's transition driver 0x420b58
 * only ever INVALIDATES the keeper (2D exit); nothing in the per-frame path
 * validates it (Ghidra 20260714-191142), so P2 stayed 3D. v2 fires on any
 * form mismatch and, for the to-2D direction, calls the native
 * ActorDimensionKeeper::validate on the landed player: the next control tick
 * then runs the native trio (keeper update sets mIs2D from the already-true
 * in2D, model changer swaps, driver snap2DGravityPoseWithRotateCenter fixes
 * pose/gravity). The to-3D direction needs no help: valid+is2D with in2D=0
 * flips to 3D natively (driver pushOutFrom2DArea + invalidate). */
#define PATCH_0016_ENABLED 1

 
#define PATCH_0017_ENABLED 1
#define PATCH_0016_FALL_TIMEOUT_FRAMES 120
/* v3: the to-3D direction CYCLES instead of stalling (run 20-22-39: three
 * startRecovery fires ~4 s apart in ONE Abyss episode): the 2D-form player
 * falls through the 3D world into a death/abyss area, which restarts the
 * recovery before the fall reaches 120 frames (~90 per cycle), so v2's
 * force-land never fired. There is no native landing to wait for in this
 * direction (2D-only collision filter, no 3D ground), so fire early. */
#define PATCH_0016_FALL_TIMEOUT_TO3D_FRAMES 45

/* PATCH-0010: per-player terminal death + delayed individual respawn. The
 * user-facing delay is loaded from settings.ini; the game tick rate remains an
 * internal conversion invariant. The countdown starts only after the native
 * PlayerStateDamageLife death animation completes. */
#define PATCH_0010_ENABLED 1

 
#define PATCH_0018_ENABLED 1
constexpr unsigned PATCH_0010_GAME_TICKS_PER_SECOND = 60;

/* PATCH-0019: Recommendation A + Tier A coin-race core. Scores are private,
 * display-only sidecars; Odyssey's native shared coin economy is untouched.
 * The first player to the configured target gets a visual winner marker, but
 * gameplay and native coin spending continue normally. */
#define PATCH_0019_ENABLED 1

/* PATCH-0020: promote the runtime-confirmed ShineGet sender selector to
 * permanent per-player moon crediting and persist scores per native save ID
 * and world ID in a checksummed two-slot journal beside Odyssey's save. */
#define PATCH_0020_ENABLED 1

/* PATCH-0021: extend PATCH-0020's crash-safe per-save/per-world journal to
 * the private coin scoreboard. A version-2 journal stores both competition
 * rows and migrates all moon records from PATCH-0020's version-1 files. */
#define PATCH_0021_ENABLED 1

/* PATCH-0022: classify accepted ShineGet before native setGotShine. Repeat
 * moons award five coins to the known collector and never increment a moon
 * sidecar. Coalesce burst credits before touching the save:/ journal. */
#define PATCH_0022_ENABLED 1

/* PATCH-0023: never touch OCoop's direct save:/ journal while Odyssey's
 * SaveDataDirector owns an asynchronous read/write/commit sequence. Two
 * independent crashes reached NinSaveFileDevice::tryCommit on the native save
 * thread after sidecar persistence was introduced; the 2026-07-17 hardware
 * fatal aborted inside nn::fs::CreateFile below CommitSaveData while the HUD
 * showed Saving.... Busy writes remain dirty and retry after PATCH-0022's
 * existing coalescing interval. */
#define PATCH_0023_ENABLED 1

/* PATCH-0024: DemoChangeWorldScene deliberately continues executing player
 * movement after the retiring StageScene is gone. Detach our cached
 * StageSceneLayout-owned HUD pointers at the exact change-world talk entry so
 * PATCH-0006's per-player callback cannot dereference freed layout actors. */
#define PATCH_0024_ENABLED 1

/* PATCH-0025: one shared camera, controllable by either player's right stick.
 * Native calcCameraMoveInput stays authoritative for P1; mirror P2's exact
 * PlayerInfo->mInput->getStickCameraRaw read and replace the output only when
 * P2's deflection is larger (P1 wins ties; both-neutral stays neutral - no
 * drift, no double speed). Solo play: tryGetPlayerActor(.,1) is nullptr ->
 * bit-identical native. Camera reset (L/R) and zoom (ZL/ZR) stay P1-only in v1
 * by design. */
#define PATCH_0025_ENABLED 1

/* PATCH-0026: the custom shared MoonTotal pane follows the current kingdom.
 * The prior getTotalShineNum(holder,-1) was save-wide, so Cascade's count was
 * carried into Sand. Use the native current-world getGotShineNum producer. */
#define PATCH_0026_ENABLED 1

/* PATCH-0027: Grand Shines credit three private competition moons. Ghidra run
 * 20260718-142945 proves Shine::setGrandShine writes 2 to Shine+0x1a0 and
 * Shine::receiveMsg branches on that same typed field. Read it before Orig;
 * PATCH-0022's existing pre-Orig isGot selector still suppresses repeats. */
#define PATCH_0027_ENABLED 1

/* PATCH-0028: preserve the punching player's sensor when BlockBrick2D accepts
 * PlayerUpperPunch2D. Native BlockStateSingleItem stores the block's own
 * receiver sensor at +0x28 before appearItemFromObj consumes it as attacker
 * provenance. Replace only that proven field after Orig. Coin2D's automatic
 * CountUp path bypasses PATCH-0019's existing Coin2D::receiveMsg hook, so the
 * accepted one-shot single-coin brick also receives one private score credit;
 * Odyssey remains solely responsible for the native total and item spawn. */
#define PATCH_0028_ENABLED 1

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_011.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_012.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_013.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_014.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_015.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_016.inc"
#endif

/* PATCH-0015: preserve the stock full miss only when both registered players
 * are simultaneously terminal. A replace hook uses no trampoline record. */
#define PATCH_0015_ENABLED 1

static bool IsPtr8(uintptr_t p) {
    return p > 0x10000 && p < 0x8000000000UL && (p & 7) == 0;
}

/* Resolve a game function pointer from its NSO offset (exlaunch adds the base). */
template <typename T>
static T OcoopFn(ptrdiff_t nso) {
    return reinterpret_cast<T>(exl::util::modules::GetTargetOffset(nso));
}

#if PATCH_0014_ENABLED
/* Scene-owned, fixed-corner P2 CounterLife. This is intentionally event-driven:
 * PATCH-0009 calls NotifyHealth only when the private sidecar changes; there is
 * no per-frame health poll or player-follow position calculation. */
namespace p2hud {
constexpr size_t kCounterLifeSize = 0x140;  // CounterLifeCtrl ctor allocation, Ghidra 20260711-200209

struct Vec2 { float x, y; };
static void* sCounter = nullptr;
static void* sOwner = nullptr;
static int sPendingHealth = PATCH_0009_P2_HEALTH_MAX;
static int sPendingMaxHealth = PATCH_0009_P2_HEALTH_MAX;
static float sGaugeMax = 0.0f;

/* Blue bonus tier (CounterLifeUp). P1's native CounterLifeCtrl builds a SECOND
 * CounterLife from the same LayoutInitInfo with resName "CounterLifeUp" (a
 * distinct archive that renders the blue hearts above the green three) and shows
 * it only when hp exceeds the normal max of 3. We mirror that exactly so P2's
 * six-heart HUD matches P1. Zero extra hooks: this rides inside the existing
 * PATCH-0014 ctor/end lifecycle. The green tier below now uses the NORMAL max (3)
 * as its gauge denominator so it saturates full at hp>=3 and the surplus shows on
 * the blue overlay — the stock CounterLifeCtrl behaviour. (Ghidra + decomp
 * OdysseyDecomp\src\Layout\CounterLifeCtrl.cpp: setCount / calcLifeUpCount /
 * isActiveCounterLifeUp; CounterLife.cpp: the "CounterLifeUp" resName branch.) */
constexpr int kP2NormalMax = PATCH_0009_P2_HEALTH_MAX;  // 3 — first-tier heart count
static void* sCounterUp = nullptr;
static float sGaugeMaxUp = 0.0f;
static bool sUpVisible = false;
 
static bool sHiddenBySceneEnd = false;

static void* AsIUseLayout(void* counter) {
    /* LayoutActor's IUseLayout subobject. CounterLifeCtrl C1 passes
     * counter+0x08 to getPaneLocalTrans (Ghidra 20260712-205638). */
    return IsPtr8((uintptr_t)counter) ? (void*)((uintptr_t)counter + 0x08) : nullptr;
}

static void* AsIUseLayoutAction(void* counter) {
    /* Separate multiple-inheritance base: CounterLife::setEmpty passes
     * counter+0x10 to getActionFrameMax (Ghidra 20260712-205638). Using +0x08
     * here calls through IUseLayout's vtable and produced the v3 null crash. */
    return IsPtr8((uintptr_t)counter) ? (void*)((uintptr_t)counter + 0x10) : nullptr;
}

static const char16_t* HealthText(int hp) {
    static constexpr char16_t k0[] = u"0";
    static constexpr char16_t k1[] = u"1";
    static constexpr char16_t k2[] = u"2";
    static constexpr char16_t k3[] = u"3";
    static constexpr char16_t k4[] = u"4";
    static constexpr char16_t k5[] = u"5";
    static constexpr char16_t k6[] = u"6";
    switch (hp) {
    case 0: return k0;
    case 1: return k1;
    case 2: return k2;
    case 3: return k3;
    case 4: return k4;
    case 5: return k5;
    default: return k6;
    }
}

/* Blue bonus overlay: the hearts ABOVE the normal three, on their own gauge of
 * max 3. Appears only while hp>3 and is killed back to hidden at hp<=3, matching
 * P1's isActiveCounterLifeUp gate. sUpVisible tracks the appear/kill edge so we
 * do not re-appear or re-kill every health tick. Fully self-contained: if the up
 * counter failed to construct (null), this is a no-op and the green tier still
 * works exactly as the verified PATCH-0014 did. */
static void ApplyBonus(int hp) {
    if (!IsPtr8((uintptr_t)sCounterUp) || sGaugeMaxUp <= 0.0f)
        return;
    auto appear = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeAppear);
    auto start = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeStart);
    auto kill = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeKill);
    auto setCount = OcoopFn<void (*)(void*, float)>(PatchOffsets::CounterLifeSetCount);
    auto setPaneString = OcoopFn<void (*)(void*, const char*, const char16_t*)>(
        PatchOffsets::LayoutSetPaneString);
    if (hp > kP2NormalMax) {
        int bonus = hp - kP2NormalMax;
        if (bonus > 3) bonus = 3;
        /* v8: while the scene-layout end has the HUD demo-hidden, keep feeding
         * gauge/text (native-sanctioned on killed layouts — the stock ctrl ctor
         * does the same) but do not appear the blue tier mid-demo; the restore
         * path clears the flag and re-runs ApplyHealth. */
        if (!sUpVisible && !sHiddenBySceneEnd) {
            appear(sCounterUp);
            start(sCounterUp);
            sUpVisible = true;
        }
        const float frame = sGaugeMaxUp - sGaugeMaxUp * (float)bonus / 3.0f;
        setCount(sCounterUp, frame);
        /* The up overlay renders ON TOP of the green counter, so its TxtLife is
         * the numeral the player sees. Native CounterLifeCtrl::setCount writes
         * the TOTAL count to every counter's TxtLife (Matching source line 88);
         * writing the bonus here showed "3" at six hearts (user screenshot
         * 2026-07-14). */
        setPaneString(AsIUseLayout(sCounterUp), "TxtLife", HealthText(hp));
    } else if (sUpVisible) {
        kill(sCounterUp);
        sUpVisible = false;
    }
}

static void ApplyHealth(int hp) {
    if (!IsPtr8((uintptr_t)sCounter) || sGaugeMax <= 0.0f)
        return;
    if (hp < 0) hp = 0;
    if (sPendingMaxHealth < PATCH_0009_P2_HEALTH_MAX)
        sPendingMaxHealth = PATCH_0009_P2_HEALTH_MAX;
    if (sPendingMaxHealth > 6)
        sPendingMaxHealth = 6;
    if (hp > sPendingMaxHealth) hp = sPendingMaxHealth;
    /* Green normal tier: the first three hearts. Denominator is the NORMAL max
     * (3), so the gauge saturates full at hp>=3 (frame clamps at 0) and any
     * surplus is shown by the blue overlay — not squeezed into the green bar.
     * For the verified hp<=3 case this is identical to the old hp/max formula. */
    int greenHp = hp;
    if (greenHp > kP2NormalMax) greenHp = kP2NormalMax;
    const float frame = sGaugeMax - sGaugeMax * (float)greenHp / (float)kP2NormalMax;
    auto setCount = OcoopFn<void (*)(void*, float)>(PatchOffsets::CounterLifeSetCount);
    auto setPaneString = OcoopFn<void (*)(void*, const char*, const char16_t*)>(
        PatchOffsets::LayoutSetPaneString);
    setCount(sCounter, frame);
    setPaneString(AsIUseLayout(sCounter), "TxtLife", HealthText(hp));
    ApplyBonus(hp);
}

static void NotifyHealth(int hp, int maxHealth) {
    sPendingHealth = hp;
    sPendingMaxHealth = maxHealth;
    ApplyHealth(hp);
}

 
#if PATCH_0014_CAPTURE_RESTORE_ENABLED
static void RestoreAfterCapture(unsigned ticks) {
    if (!IsPtr8((uintptr_t)sCounter))
        return;
    auto isActive = OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsActiveLayout);
    const bool activeBefore = isActive(sCounter);
    if (activeBefore) {
        Logging.Log("[OCoop] PATCH-0014 capture check activeBefore=1 applied=0 hp=%d ticks=%u",
                    sPendingHealth, ticks);
        return;
    }
    auto appear = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeAppear);
    auto start = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeStart);
    appear(sCounter);
    start(sCounter);
    sUpVisible = false;
    ApplyHealth(sPendingHealth);
    Logging.Log("[OCoop] PATCH-0014 capture check activeBefore=0 applied=1 hp=%d ticks=%u",
                sPendingHealth, ticks);
}
#endif

static void DetachForSceneReset() {
    /* A full-miss reload can bypass StageSceneLayout::end. The old layout and
     * CounterLife then belong to the retiring scene even though their numeric
     * addresses still pass IsPtr8. Drop the handles at the proven new-scene
     * boundary before ResetP2Health publishes the next scene's pending value. */
    if (sCounter != nullptr || sOwner != nullptr) {
        Logging.Log("[OCoop] PATCH-0014 HUD detached for scene reset counter=%p up=%p owner=%p",
                    sCounter, sCounterUp, sOwner);
    }
    sCounter = nullptr;
    sCounterUp = nullptr;
    sOwner = nullptr;
    sGaugeMax = 0.0f;
    sGaugeMaxUp = 0.0f;
    sUpVisible = false;
    sHiddenBySceneEnd = false;
}

static void Create(void* owner, const void* layoutInitInfo) {
    if (!IsPtr8((uintptr_t)owner) || !IsPtr8((uintptr_t)layoutInitInfo))
        return;
    /* Scene end clears the old pointer. Never touch a previous-scene HUD here. */
    sCounter = ::operator new(kCounterLifeSize);
    if (!sCounter)
        return;
    auto ctor = OcoopFn<void (*)(void*, const char*, const char*, const void*)>(
        PatchOffsets::CounterLifeCtor);
    auto getFrameMax = OcoopFn<float (*)(const void*, const char*, const char*)>(
        PatchOffsets::LayoutGetActionFrameMax);
    auto setPaneTrans = OcoopFn<void (*)(void*, const char*, const Vec2&)>(
        PatchOffsets::LayoutSetPaneLocalTrans2);
    ctor(sCounter, "[OCoop]P2Life", "CounterLife", layoutInitInfo);
    sOwner = owner;
    sGaugeMax = getFrameMax(AsIUseLayoutAction(sCounter), "Gauge", "Gauge");
    /* Last runtime-confirmed visible placement. Editable HUD offsets are
     * retired until a stable two-axis layout lever is proven. */
    const Vec2 fixedCorner = {460.0f, 0.0f};
    setPaneTrans(AsIUseLayout(sCounter), "All", fixedCorner);

    /* Blue bonus overlay, built from the SAME LayoutInitInfo with the
     * "CounterLifeUp" archive (P1's CounterLifeCtrl constructs its three counters
     * from one info the same way). Same fixed corner as the green tier — the blue
     * hearts sit above the green inside the archive's own pane layout, exactly as
     * P1 overlays them. Start hidden; ApplyBonus reveals it only when hp>3. */
    sCounterUp = ::operator new(kCounterLifeSize);
    sGaugeMaxUp = 0.0f;
    sUpVisible = false;
    sHiddenBySceneEnd = false;
    if (IsPtr8((uintptr_t)sCounterUp)) {
        ctor(sCounterUp, "[OCoop]P2LifeUp", "CounterLifeUp", layoutInitInfo);
        sGaugeMaxUp = getFrameMax(AsIUseLayoutAction(sCounterUp), "Gauge", "Gauge");
        setPaneTrans(AsIUseLayout(sCounterUp), "All", fixedCorner);
        auto kill = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeKill);
        kill(sCounterUp);  // hidden until a bonus tier exists
    }

    Logging.Log("[OCoop] PATCH-0014 HUD created counter=%p up=%p owner=%p gaugeMax=%.1f/%.1f fixedPane=(%.0f,%.0f)",
                sCounter, sCounterUp, owner, (double)sGaugeMax, (double)sGaugeMaxUp,
                (double)fixedCorner.x, (double)fixedCorner.y);
    ApplyHealth(sPendingHealth);
    Logging.Log("[OCoop] PATCH-0014 HUD initialized health=%d", sPendingHealth);
}

static void Appear(void* owner) {
    if (owner != sOwner || !IsPtr8((uintptr_t)sCounter))
        return;
    auto appear = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeAppear);
    auto start = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeStart);
    appear(sCounter);
    start(sCounter);
    ApplyHealth(sPendingHealth);
}

/* v6 capture-hide fix. Ghidra run 20260713-155149: scene demos (the capture
 * cinematic among them) hide the gameplay HUD via StageSceneLayout::endWithoutCoin
 * (15 demo-director callers), and the game restores its stock layouts in
 * StageSceneLayout::start 0x20ca20 (CounterLifeCtrl::appear, MapMini, coin
 * counter, ...). P1's counter therefore returns after every capture demo while
 * our unmanaged counter stayed hidden — nothing re-appeared it. Restore ours at
 * the exact same boundary. The isActive gate keeps the normal scene start (and
 * any start() where nothing hid us) a no-op, and doubles as the discriminator:
 * if the user still sees no HUD while this logs active=1, the hide is not
 * actor-level and the next lever must be found. */
static void OnLayoutStart(void* owner) {
    if (owner != sOwner || !IsPtr8((uintptr_t)sCounter))
        return;
    auto isActive = OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsActiveLayout);
    bool active = isActive(sCounter);
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_017.inc"
#endif
    if (active)
        return;
    auto appear = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeAppear);
    auto start = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeStart);
    appear(sCounter);
    start(sCounter);
    /* The demo hid the blue tier too (if shown). Reset the edge flag so
     * ApplyBonus re-appears it when hp is still above the normal max. */
    sUpVisible = false;
    sHiddenBySceneEnd = false;
    ApplyHealth(sPendingHealth);
    Logging.Log("[OCoop] PATCH-0014 HUD reappear after demo hide hp=%d", sPendingHealth);
}

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_018.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_019.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_020.inc"
#endif

 
static void End(void* owner) {
    if (owner != sOwner)
        return;
    auto kill = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeKill);
    if (IsPtr8((uintptr_t)sCounter))
        kill(sCounter);
    if (IsPtr8((uintptr_t)sCounterUp))
        kill(sCounterUp);
    sUpVisible = false;
    sHiddenBySceneEnd = true;
    Logging.Log("[OCoop] PATCH-0014 v8 HUD hidden by scene-layout end (kept for demo restore) hp=%d",
                sPendingHealth);
}

 
static void TickDemoRestore(void* anyPlayer) {
    if (!sHiddenBySceneEnd || !IsPtr8((uintptr_t)sCounter) || !IsPtr8((uintptr_t)anyPlayer))
        return;
    auto isActiveDemo = OcoopFn<bool (*)(const void*)>(PatchOffsets::RsIsActiveDemoActor);
    if (isActiveDemo(anyPlayer))
        return;
    auto isActive = OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsActiveLayout);
    if (isActive(sCounter)) {
        /* Something else already re-appeared it (scene-start restore). */
        sHiddenBySceneEnd = false;
        return;
    }
    auto appear = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeAppear);
    auto start = OcoopFn<void (*)(void*)>(PatchOffsets::CounterLifeStart);
    appear(sCounter);
    start(sCounter);
    sUpVisible = false;  /* ApplyHealth re-appears the blue tier if hp>3 */
    sHiddenBySceneEnd = false;
    ApplyHealth(sPendingHealth);
    Logging.Log("[OCoop] PATCH-0014 v8 HUD restore after demo hp=%d", sPendingHealth);
}
}

#if PATCH_0019_ENABLED
/* Scoreboard-only coin race. The two counters are real Odyssey
 * CounterCollectCoin layouts, but +0x14c mIsUpdateCount is cleared so neither
 * reads or mirrors the native shared economy. Only Credit() mutates the
 * display-side sidecars. */
namespace coinrace {
constexpr size_t kLayoutActorSize = 0x130;
constexpr int kMaxDisplayScore = 999;
constexpr uintptr_t kNativeCoinOffset = 0x18;
constexpr uintptr_t kNativeShineOffset = 0x28;
constexpr uintptr_t kNativePurpleOffset = 0x30;

struct Vec2 { float x, y; };
static int sScores[2] = {0, 0};
static int sMoonScores[2] = {0, 0};
static int sWinner = -1;
static int sMoonWinner = -1;
static void* sHud = nullptr;
static void* sOwner = nullptr;
static bool sHiddenBySceneEnd = false;
static int sCountUpPlayer = -1;
static unsigned sCountUpDepth = 0;
static unsigned sSharedPollDivider = 0;
static int sLastSharedCoin = -1;
static int sLastPurple = -1;
static int sLastPurpleMax = -1;
static int sLastSharedMoon = -1;
#if PATCH_0022_ENABLED
constexpr int kRepeatMoonCoinReward = 5;
constexpr unsigned kRepeatMoonRewardTimeoutTicks = 360;
static int sRepeatMoonPlayer = -1;
static int sRepeatMoonCoinsRemaining = 0;
static unsigned sRepeatMoonRewardTicks = 0;
#endif

static char16_t sCoinText[2][8] = {};
static char16_t sMoonMultiplierText[2][12] = {};
static char16_t sSharedCoinText[12] = {};
static char16_t sPurpleText[12] = {};
static char16_t sSharedMoonText[8] = {};

#if PATCH_0020_ENABLED
static bool sCompetitionPersistReady = false;
static void LoadCompetitionScoresForActiveWorld();
static bool SaveCompetitionScoresForActiveWorld();
#if PATCH_0022_ENABLED
static void MarkCompetitionPersistenceDirty();
static bool FlushCompetitionPersistence(const char* reason);
static void TickCompetitionPersistence();
static void TickRepeatMoonReward();
#endif
#endif

static void* AsIUseLayout(void* counter) {
    return IsPtr8((uintptr_t)counter)
        ? (void*)((uintptr_t)counter + 0x08) : nullptr;
}

static int ClampDisplay(int value, int maxValue) {
    if (value < 0)
        return 0;
    return value > maxValue ? maxValue : value;
}

/* Native counters render values without zero padding; text panes are
 * left-aligned (Txt1Pane LineAlign::Left), so shorter strings only free
 * trailing space and cannot overlap a neighbour. Returns the length. */
static int FormatUnpadded(char16_t* out, int value, int maxValue) {
    value = ClampDisplay(value, maxValue);
    char16_t reversed[8];
    int len = 0;
    do {
        reversed[len++] = (char16_t)(u'0' + value % 10);
        value /= 10;
    } while (value > 0);
    for (int i = 0; i < len; ++i)
        out[i] = reversed[len - 1 - i];
    out[len] = 0;
    return len;
}

static void FormatSharedCoin(int value) {
    value = ClampDisplay(value, 999999);
    if (value < 1000) {
        FormatUnpadded(sSharedCoinText, value, 999);
        return;
    }
    const int len = FormatUnpadded(sSharedCoinText, value / 1000, 999);
    sSharedCoinText[len] = u',';
    char16_t* tail = sSharedCoinText + len + 1;
    const int rem = value % 1000;
    tail[0] = (char16_t)(u'0' + (rem / 100) % 10);
    tail[1] = (char16_t)(u'0' + (rem / 10) % 10);
    tail[2] = (char16_t)(u'0' + rem % 10);
    tail[3] = 0;
}

static void FormatPurple(int current, int maximum) {
    const int len = FormatUnpadded(sPurpleText, current, 999);
    sPurpleText[len] = u'/';
    FormatUnpadded(sPurpleText + len + 1, maximum, 999);
}

static void FormatMultiplier(int idx, int value) {
    char16_t* out = sMoonMultiplierText[idx];
    out[0] = u'x';
    out[1] = u' ';
    value = ClampDisplay(value, 999);
    int cursor = 2;
    if (value >= 100)
        out[cursor++] = (char16_t)(u'0' + (value / 100) % 10);
    if (value >= 10)
        out[cursor++] = (char16_t)(u'0' + (value / 10) % 10);
    out[cursor++] = (char16_t)(u'0' + value % 10);
    out[cursor] = 0;
}

static void SetText(const char* pane, const char16_t* text) {
    if (!IsPtr8((uintptr_t)sHud))
        return;
    auto setPaneString = OcoopFn<void (*)(void*, const char*, const char16_t*)>(
        PatchOffsets::LayoutSetPaneString);
    setPaneString(AsIUseLayout(sHud), pane, text);
}

static void SetTextShadowed(const char* pane, const char* shadowPane,
                            const char16_t* text) {
    SetText(shadowPane, text);
    SetText(pane, text);
}

static void SetVisible(const char* pane, bool visible) {
    if (!IsPtr8((uintptr_t)sHud))
        return;
    auto setVisible = OcoopFn<void (*)(void*, const char*)>(
        visible ? PatchOffsets::LayoutShowPane : PatchOffsets::LayoutHidePane);
    setVisible(AsIUseLayout(sHud), pane);
}

static void SetVisibleShadowed(const char* pane, const char* shadowPane,
                               bool visible) {
    SetVisible(shadowPane, visible);
    SetVisible(pane, visible);
}

static void ApplyStaticText() {
    SetText("IconGoldCoin", u"@");
    SetText("IconPurpleCoin", u"@");
    SetText("IconP1Coin", u"@");
    SetText("IconP2Coin", u"@");
    SetText("IconMoonTotal", u"p");
    static constexpr const char* kMoonPanes[2][5] = {
        {"MoonP1_1", "MoonP1_2", "MoonP1_3", "MoonP1_4", "MoonP1_5"},
        {"MoonP2_1", "MoonP2_2", "MoonP2_3", "MoonP2_4", "MoonP2_5"}
    };
    for (int player = 0; player < 2; ++player)
        for (int slot = 0; slot < 5; ++slot)
            SetText(kMoonPanes[player][slot], u"p");
}

static void ApplyPlayerScores() {
    /* User-removed 2026-07-16: no winner marker on the labels. sWinner /
     * sMoonWinner stay tracked (WINNER log lines + journal fields unchanged). */
    SetTextShadowed("LblPlayer1", "LblPlayer1Sh", u"P1:");
    SetTextShadowed("LblPlayer2", "LblPlayer2Sh", u"P2:");
    for (int idx = 0; idx < 2; ++idx)
        FormatUnpadded(sCoinText[idx], sScores[idx], 999);
    SetTextShadowed("CoinP1", "CoinP1Sh", sCoinText[0]);
    SetTextShadowed("CoinP2", "CoinP2Sh", sCoinText[1]);

    static constexpr const char* kMoonPanes[2][5] = {
        {"MoonP1_1", "MoonP1_2", "MoonP1_3", "MoonP1_4", "MoonP1_5"},
        {"MoonP2_1", "MoonP2_2", "MoonP2_3", "MoonP2_4", "MoonP2_5"}
    };
    static constexpr const char* kCountPanes[2] = {"MoonP1Count", "MoonP2Count"};
    for (int player = 0; player < 2; ++player) {
        const int count = sMoonScores[player];
        const bool collapsed = count >= 6;
        const int visibleIcons = collapsed ? 1 : count;
        for (int slot = 0; slot < 5; ++slot)
            SetVisible(kMoonPanes[player][slot], slot < visibleIcons);
        if (collapsed) {
            FormatMultiplier(player, count);
            static constexpr const char* kCountShadowPanes[2] = {
                "MoonP1CountSh", "MoonP2CountSh"
            };
            SetTextShadowed(kCountPanes[player], kCountShadowPanes[player],
                            sMoonMultiplierText[player]);
            SetVisibleShadowed(kCountPanes[player], kCountShadowPanes[player], true);
        } else {
            static constexpr const char* kCountShadowPanes[2] = {
                "MoonP1CountSh", "MoonP2CountSh"
            };
            SetVisibleShadowed(kCountPanes[player], kCountShadowPanes[player], false);
        }
    }
}

static void* ResolveGameDataHolder() {
    if (!IsPtr8((uintptr_t)sHud))
        return nullptr;
    void* holder = nullptr;
    auto ctor = OcoopFn<void (*)(void**, const void*)>(
        PatchOffsets::GameDataHolderAccessorCtor);
    ctor(&holder, (const void*)((uintptr_t)sHud + 0x38));
    return IsPtr8((uintptr_t)holder) ? holder : nullptr;
}

static void ApplySharedTotals(bool force) {
    void* holder = ResolveGameDataHolder();
    if (!holder)
        return;
    auto getCoin = OcoopFn<int (*)(void*)>(PatchOffsets::GameDataGetCoinNum);
    auto getPurple =
        OcoopFn<int (*)(void*)>(PatchOffsets::GameDataGetCoinCollectNum);
    auto getPurpleMax =
        OcoopFn<int (*)(void*)>(PatchOffsets::GameDataGetCoinCollectNumMax);
#if PATCH_0026_ENABLED
    auto getMoon =
        OcoopFn<int (*)(void*, int)>(PatchOffsets::GameDataGetGotShineNum);
#else
    auto getMoon =
        OcoopFn<int (*)(void*, int)>(PatchOffsets::GameDataGetTotalShineNum);
#endif
    const int coin = getCoin(holder);
    const int purple = getPurple(holder);
    const int purpleMax = getPurpleMax(holder);
    const int moon = getMoon(holder, -1);
#if PATCH_0026_ENABLED
    auto getWorld =
        OcoopFn<int (*)(void*)>(PatchOffsets::GameDataGetCurrentWorldId);
    const int world = getWorld(holder);
    static int lastLoggedWorld = -999;
    static unsigned logCount = 0;
    if (logCount < 8 && world != lastLoggedWorld) {
        ++logCount;
        lastLoggedWorld = world;
        Logging.Log("[OCoop] PATCH-0026 kingdom moon total world=%d moon=%d",
                    world, moon);
    }
#endif
    if (force || coin != sLastSharedCoin) {
        FormatSharedCoin(coin);
        SetTextShadowed("CoinTotal", "CoinTotalSh", sSharedCoinText);
        sLastSharedCoin = coin;
    }
    if (force || purple != sLastPurple || purpleMax != sLastPurpleMax) {
        FormatPurple(purple, purpleMax);
        SetTextShadowed("PurpleTotal", "PurpleTotalSh", sPurpleText);
        sLastPurple = purple;
        sLastPurpleMax = purpleMax;
    }
    if (force || moon != sLastSharedMoon) {
        FormatUnpadded(sSharedMoonText, moon, 999);
        SetTextShadowed("MoonTotal", "MoonTotalSh", sSharedMoonText);
        sLastSharedMoon = moon;
    }
}

static void ApplyAll() {
    ApplyStaticText();
    ApplyPlayerScores();
    ApplySharedTotals(true);
}

static void HideNativeCounters() {
    if (!IsPtr8((uintptr_t)sOwner))
        return;
    /* Keep the native counter actors alive. StageSceneStateGetShine drives the
     * moon-get demo through StageSceneLayout::startShineCountAnim() and waits
     * on isEndShineCountAnim(); killing mShineCounter for presentation can
     * therefore leave the demo waiting forever. Hide only each layout's root
     * pane so native nerves/actions continue to advance behind OCoop's panel. */
    auto hidePane = OcoopFn<void (*)(void*, const char*)>(
        PatchOffsets::LayoutHidePane);
    void* coin = *(void**)((uintptr_t)sOwner + kNativeCoinOffset);
    void* shine = *(void**)((uintptr_t)sOwner + kNativeShineOffset);
    void* purple = *(void**)((uintptr_t)sOwner + kNativePurpleOffset);
    if (IsPtr8((uintptr_t)coin))
        hidePane(AsIUseLayout(coin), "All");
    if (IsPtr8((uintptr_t)purple))
        hidePane(AsIUseLayout(purple), "All");
    if (IsPtr8((uintptr_t)shine))
        hidePane(AsIUseLayout(shine), "All");
}

static void DetachForSceneReset() {
    if (sHud != nullptr || sOwner != nullptr) {
        Logging.Log("[OCoop] PATCH-0019 combined HUD detached for scene reset hud=%p owner=%p",
                    sHud, sOwner);
    }
    sHud = nullptr;
    sOwner = nullptr;
    sHiddenBySceneEnd = false;
    sSharedPollDivider = 0;
    sLastSharedCoin = -1;
    sLastPurple = -1;
    sLastPurpleMax = -1;
    sLastSharedMoon = -1;
}

static void ResetRound() {
#if PATCH_0022_ENABLED
    FlushCompetitionPersistence("scene-reset");
    sRepeatMoonPlayer = -1;
    sRepeatMoonCoinsRemaining = 0;
    sRepeatMoonRewardTicks = 0;
#endif
    DetachForSceneReset();
#if PATCH_0020_ENABLED
    sCompetitionPersistReady = false;
#endif
    sScores[0] = 0;
    sScores[1] = 0;
    sMoonScores[0] = 0;
    sMoonScores[1] = 0;
    sWinner = -1;
    sMoonWinner = -1;
    Logging.Log("[OCoop] PATCH-0019 scene state cleared pending persistent load coin-target=%d moon-target=%d enabled=%d/%d",
                ocoop::config::Get().coinRaceTarget,
                ocoop::config::Get().moonRaceTarget,
                ocoop::config::Get().coinRaceEnabled ? 1 : 0,
                ocoop::config::Get().moonRaceEnabled ? 1 : 0);
}

static void Create(void* owner, const void* layoutInitInfo) {
    const auto& settings = ocoop::config::Get();
    if ((!settings.coinRaceEnabled && !settings.moonRaceEnabled) ||
        !IsPtr8((uintptr_t)owner) || !IsPtr8((uintptr_t)layoutInitInfo))
        return;

    sOwner = owner;
    sHud = ::operator new(kLayoutActorSize);
    if (!IsPtr8((uintptr_t)sHud))
        return;
    auto ctor = OcoopFn<void (*)(void*, const char*)>(PatchOffsets::LayoutActorCtor);
    auto init = OcoopFn<void (*)(void*, const void*, const char*, const char*)>(
        PatchOffsets::LayoutActorInit);
    auto setPaneTrans = OcoopFn<void (*)(void*, const char*, const Vec2&)>(
        PatchOffsets::LayoutSetPaneLocalTrans2);
    auto appear = OcoopFn<void (*)(void*)>(PatchOffsets::LayoutActorAppear);
    ctor(sHud, "[OCoop] Competition Scoreboard");
    init(sHud, layoutInitInfo, "OCoopScoreBoard", nullptr);
    const Vec2 pos = {settings.competitionHudX, settings.competitionHudY};
    setPaneTrans(AsIUseLayout(sHud), "All", pos);
#if PATCH_0020_ENABLED
    LoadCompetitionScoresForActiveWorld();
#endif
    ApplyAll();
    appear(sHud);
    HideNativeCounters();
    Logging.Log("[OCoop] PATCH-0019 combined HUD created hud=%p owner=%p panel=(%.0f,%.0f) native-panes-hidden actors-live",
                sHud, owner, (double)settings.competitionHudX,
                (double)settings.competitionHudY);
}

static void End(void* owner) {
    if (owner != sOwner)
        return;
    auto kill = OcoopFn<void (*)(void*)>(PatchOffsets::AlLayoutActorKill);
    if (IsPtr8((uintptr_t)sHud))
        kill(sHud);
    sHiddenBySceneEnd = true;
    Logging.Log("[OCoop] PATCH-0019 combined HUD hidden by scene-layout end coin=%d:%d moon=%d:%d",
                sScores[0], sScores[1], sMoonScores[0], sMoonScores[1]);
}

static void Restore() {
    auto appear = OcoopFn<void (*)(void*)>(PatchOffsets::LayoutActorAppear);
    if (IsPtr8((uintptr_t)sHud))
        appear(sHud);
    sHiddenBySceneEnd = false;
    ApplyAll();
    HideNativeCounters();
}

static void OnLayoutStart(void* owner) {
    if (owner != sOwner || !IsPtr8((uintptr_t)sHud))
        return;
    HideNativeCounters();
    auto isActive = OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsActiveLayout);
    if (isActive(sHud)) {
        sHiddenBySceneEnd = false;
        return;
    }
    Restore();
    Logging.Log("[OCoop] PATCH-0019 combined HUD restored by scene-layout start");
}

static void TickDemoRestore(void* anyPlayer) {
    if (!IsPtr8((uintptr_t)sHud) || !IsPtr8((uintptr_t)anyPlayer))
        return;
#if PATCH_0022_ENABLED
    TickCompetitionPersistence();
    TickRepeatMoonReward();
#endif
    HideNativeCounters();
    if (!sHiddenBySceneEnd) {
        if (++sSharedPollDivider >= 4) {
            sSharedPollDivider = 0;
            ApplySharedTotals(false);
        }
        return;
    }
    auto isActiveDemo = OcoopFn<bool (*)(const void*)>(PatchOffsets::RsIsActiveDemoActor);
    if (isActiveDemo(anyPlayer))
        return;
    auto isActive = OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsActiveLayout);
    if (isActive(sHud)) {
        sHiddenBySceneEnd = false;
        return;
    }
    Restore();
    Logging.Log("[OCoop] PATCH-0019 combined HUD restored after demo coin=%d:%d moon=%d:%d",
                sScores[0], sScores[1], sMoonScores[0], sMoonScores[1]);
}

static int ResolvePlayerIndex(const void* anchor, const void* sensor) {
    if (!IsPtr8((uintptr_t)anchor) || !IsPtr8((uintptr_t)sensor))
        return -1;
    auto getSensorHost = OcoopFn<void* (*)(const void*)>(PatchOffsets::AlGetSensorHost);
    void* host = getSensorHost(sensor);
    if (!IsPtr8((uintptr_t)host))
        return -1;
    auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
    for (int i = 0; i < 2; i++) {
        if (getPlayerActor(anchor, i) == host)
            return i;
    }
    return -1;
}

static bool IsVec3Ptr(uintptr_t p) {
    return p > 0x10000 && p < 0x8000000000UL && (p & 3) == 0;
}

static int NearestPlayerIndex(const void* coin) {
    if (!IsPtr8((uintptr_t)coin))
        return -1;
    auto getTrans = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetTrans);
    auto getPlayerActor =
        OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
    const float* coinPos = getTrans(coin);
    if (!IsVec3Ptr((uintptr_t)coinPos))
        return -1;
    int best = -1;
    float bestDist2 = 0.0f;
    for (int i = 0; i < 2; i++) {
        void* player = getPlayerActor(coin, i);
        if (!IsPtr8((uintptr_t)player))
            continue;
        const float* playerPos = getTrans(player);
        if (!IsVec3Ptr((uintptr_t)playerPos))
            continue;
        const float dx = playerPos[0] - coinPos[0];
        const float dy = playerPos[1] - coinPos[1];
        const float dz = playerPos[2] - coinPos[2];
        const float dist2 = dx * dx + dy * dy + dz * dz;
        if (best < 0 || dist2 < bestDist2) {
            best = i;
            bestDist2 = dist2;
        }
    }
    return best;
}

static void NoteIgnored(const char* source, const void* sender) {
    static unsigned logged = 0;
    if (logged >= 12)
        return;
    logged++;
    Logging.Log("[OCoop] PATCH-0019 coin ignored source=%s sender=%p reason=no-registered-player",
                source, sender);
}

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_021.inc"
#endif

static void Credit(int idx, int amount, const char* source) {
    if (!ocoop::config::Get().coinRaceEnabled || idx < 0 || idx > 1 || amount <= 0)
        return;
#if PATCH_0021_ENABLED
    if (!sCompetitionPersistReady)
        LoadCompetitionScoresForActiveWorld();
#endif
    int next = sScores[idx] + amount;
    if (next > kMaxDisplayScore)
        next = kMaxDisplayScore;
    sScores[idx] = next;
    if (sWinner < 0 && sScores[idx] >= ocoop::config::Get().coinRaceTarget) {
        sWinner = idx;
        Logging.Log("[OCoop] PATCH-0019 WINNER p=%d score=%d:%d target=%d",
                    idx + 1, sScores[0], sScores[1],
                    ocoop::config::Get().coinRaceTarget);
    }
    bool persistenceQueued = false;
#if PATCH_0022_ENABLED
    MarkCompetitionPersistenceDirty();
    persistenceQueued = sCompetitionPersistReady;
#elif PATCH_0021_ENABLED
    persistenceQueued = SaveCompetitionScoresForActiveWorld();
#endif
    ApplyAll();
    Logging.Log("[OCoop] PATCH-0019 coin source=%s idx=%d add=%d score=%d:%d target=%d winner=%d persistence-queued=%d",
                source, idx, amount, sScores[0], sScores[1],
                ocoop::config::Get().coinRaceTarget, sWinner,
                persistenceQueued ? 1 : 0);
}

#if PATCH_0020_ENABLED
/* OCoop owns this sidecar; Odyssey's GameData pools and GameData.bin are never
 * modified. Two fixed-size journal slots make an interrupted write fall back
 * to the last checksummed generation. The native save-data ID partitions SMO
 * save slots, and currentWorldId partitions kingdoms inside each save.
 * PATCH-0021 uses new version-2 files and imports PATCH-0020's version-1 moon
 * files without modifying them. */
constexpr uint32_t kLegacyMoonPersistMagic = 0x504d434f;  // "OCMP"
constexpr uint16_t kLegacyMoonPersistVersion = 1;
constexpr uint32_t kCompetitionPersistMagic = 0x5043434f;  // "OCCP"
constexpr uint16_t kCompetitionPersistVersion = 2;
constexpr int kCompetitionPersistSaveCount = 8;
constexpr int kCompetitionPersistWorldCount = 32;
constexpr const char* kLegacyMoonPersistPathA = "save:/OCoopMoonScoresA.bin";
constexpr const char* kLegacyMoonPersistPathB = "save:/OCoopMoonScoresB.bin";
constexpr const char* kCompetitionPersistPathA = "save:/OCoopCompetitionA.bin";
constexpr const char* kCompetitionPersistPathB = "save:/OCoopCompetitionB.bin";

struct LegacyMoonWorldScore {
    int32_t score[2];
    int32_t winner;
};

struct LegacyMoonSaveScore {
    int64_t saveId;
    LegacyMoonWorldScore world[kCompetitionPersistWorldCount];
};

struct LegacyMoonPersistState {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t generation;
    uint32_t checksum;
    LegacyMoonSaveScore save[kCompetitionPersistSaveCount];
};

struct CompetitionWorldScore {
    int32_t coinScore[2];
    int32_t coinWinner;
    int32_t moonScore[2];
    int32_t moonWinner;
};

struct CompetitionSaveScore {
    int64_t saveId;
    CompetitionWorldScore world[kCompetitionPersistWorldCount];
};

struct CompetitionPersistState {
    uint32_t magic;
    uint16_t version;
    uint16_t size;
    uint32_t generation;
    uint32_t checksum;
    CompetitionSaveScore save[kCompetitionPersistSaveCount];
};

static CompetitionPersistState sCompetitionPersist = {};
static int sCompetitionPersistSaveIndex = -1;
static int sCompetitionPersistWorldIndex = -1;
static int64_t sCompetitionPersistSaveId = 0;
#if PATCH_0023_ENABLED
static bool sCompetitionNativeSaveBusy = false;
static unsigned sCompetitionNativeSaveDeferrals = 0;
#endif
#if PATCH_0022_ENABLED
constexpr unsigned kCompetitionPersistCoalesceTicks = 180;
static bool sCompetitionPersistDirty = false;
static unsigned sCompetitionPersistDelayTicks = 0;
#endif

static uint32_t CalcCompetitionPersistChecksum(const CompetitionPersistState& state) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&state);
    const size_t checksumOffset = offsetof(CompetitionPersistState, checksum);
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < sizeof(CompetitionPersistState); ++i) {
        if (i >= checksumOffset && i < checksumOffset + sizeof(state.checksum))
            continue;
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    return hash;
}

static uint32_t CalcLegacyMoonPersistChecksum(const LegacyMoonPersistState& state) {
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(&state);
    const size_t checksumOffset = offsetof(LegacyMoonPersistState, checksum);
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < sizeof(LegacyMoonPersistState); ++i) {
        if (i >= checksumOffset && i < checksumOffset + sizeof(state.checksum))
            continue;
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    return hash;
}

static void InitEmptyCompetitionPersist() {
    sCompetitionPersist = {};
    sCompetitionPersist.magic = kCompetitionPersistMagic;
    sCompetitionPersist.version = kCompetitionPersistVersion;
    sCompetitionPersist.size =
        static_cast<uint16_t>(sizeof(CompetitionPersistState));
    for (int save = 0; save < kCompetitionPersistSaveCount; ++save) {
        for (int world = 0; world < kCompetitionPersistWorldCount; ++world) {
            sCompetitionPersist.save[save].world[world].coinWinner = -1;
            sCompetitionPersist.save[save].world[world].moonWinner = -1;
        }
    }
    sCompetitionPersist.checksum =
        CalcCompetitionPersistChecksum(sCompetitionPersist);
}

static bool IsValidCompetitionPersist(const CompetitionPersistState& state) {
    return state.magic == kCompetitionPersistMagic &&
           state.version == kCompetitionPersistVersion &&
           state.size == sizeof(CompetitionPersistState) &&
           state.checksum == CalcCompetitionPersistChecksum(state);
}

static bool IsValidLegacyMoonPersist(const LegacyMoonPersistState& state) {
    return state.magic == kLegacyMoonPersistMagic &&
           state.version == kLegacyMoonPersistVersion &&
           state.size == sizeof(LegacyMoonPersistState) &&
           state.checksum == CalcLegacyMoonPersistChecksum(state);
}

static bool ReadCompetitionPersist(const char* path,
                                   CompetitionPersistState* out) {
    nn::fs::FileHandle handle = {};
    if (nn::fs::OpenFile(&handle, path, nn::fs::OpenMode_Read) != 0)
        return false;
    long fileSize = 0;
    Result result = nn::fs::GetFileSize(&fileSize, handle);
    if (result == 0 &&
        fileSize == static_cast<long>(sizeof(CompetitionPersistState)))
        result = nn::fs::ReadFile(handle, 0, out,
                                  static_cast<ulong>(sizeof(CompetitionPersistState)));
    nn::fs::CloseFile(handle);
    return result == 0 &&
           fileSize == static_cast<long>(sizeof(CompetitionPersistState)) &&
           IsValidCompetitionPersist(*out);
}

static bool ReadLegacyMoonPersist(const char* path,
                                  LegacyMoonPersistState* out) {
    nn::fs::FileHandle handle = {};
    if (nn::fs::OpenFile(&handle, path, nn::fs::OpenMode_Read) != 0)
        return false;
    long fileSize = 0;
    Result result = nn::fs::GetFileSize(&fileSize, handle);
    if (result == 0 &&
        fileSize == static_cast<long>(sizeof(LegacyMoonPersistState)))
        result = nn::fs::ReadFile(handle, 0, out,
                                  static_cast<ulong>(sizeof(LegacyMoonPersistState)));
    nn::fs::CloseFile(handle);
    return result == 0 &&
           fileSize == static_cast<long>(sizeof(LegacyMoonPersistState)) &&
           IsValidLegacyMoonPersist(*out);
}

static bool WriteCompetitionPersist(const char* path) {
    nn::fs::FileHandle handle = {};
    Result result = nn::fs::OpenFile(&handle, path, nn::fs::OpenMode_Write);
    if (result != 0) {
        result = nn::fs::CreateFile(
            path, static_cast<long>(sizeof(CompetitionPersistState)));
        if (result != 0)
            return false;
        result = nn::fs::OpenFile(&handle, path, nn::fs::OpenMode_Write);
        if (result != 0)
            return false;
    }
    const nn::fs::WriteOption option = nn::fs::WriteOption::CreateOption(
        nn::fs::WriteOptionFlag_Flush);
    result = nn::fs::WriteFile(handle, 0, &sCompetitionPersist,
                               sizeof(CompetitionPersistState), option);
    nn::fs::CloseFile(handle);
    if (result != 0)
        return false;
    static CompetitionPersistState verify = {};
    return ReadCompetitionPersist(path, &verify) &&
           verify.generation == sCompetitionPersist.generation;
}

static int FindCompetitionSave(int64_t saveId, bool create) {
    int empty = -1;
    for (int i = 0; i < kCompetitionPersistSaveCount; ++i) {
        if (sCompetitionPersist.save[i].saveId == saveId)
            return i;
        if (empty < 0 && sCompetitionPersist.save[i].saveId == 0)
            empty = i;
    }
    if (!create || empty < 0)
        return -1;
    sCompetitionPersist.save[empty].saveId = saveId;
    return empty;
}

static bool ResolveCompetitionPersistKey(int64_t* saveId, int* worldId) {
    void* holder = ResolveGameDataHolder();
    if (!holder)
        return false;
    auto getSaveId = OcoopFn<int64_t (*)(void*)>(
        PatchOffsets::GameDataGetSaveDataIdForPrepo);
    auto getWorldId = OcoopFn<int (*)(void*)>(
        PatchOffsets::GameDataGetCurrentWorldId);
    *saveId = getSaveId(holder);
    *worldId = getWorldId(holder);
    return *saveId != 0 && *worldId >= 0 &&
           *worldId < kCompetitionPersistWorldCount;
}

static bool ImportLegacyMoonPersist(const char** source) {
    static LegacyMoonPersistState stateA = {};
    static LegacyMoonPersistState stateB = {};
    const bool validA = ReadLegacyMoonPersist(kLegacyMoonPersistPathA, &stateA);
    const bool validB = ReadLegacyMoonPersist(kLegacyMoonPersistPathB, &stateB);
    const LegacyMoonPersistState* legacy = nullptr;
    if (validA && (!validB ||
        static_cast<int32_t>(stateA.generation - stateB.generation) > 0)) {
        legacy = &stateA;
        *source = "legacy-A";
    } else if (validB) {
        legacy = &stateB;
        *source = "legacy-B";
    }
    if (!legacy)
        return false;

    InitEmptyCompetitionPersist();
    sCompetitionPersist.generation = legacy->generation;
    for (int save = 0; save < kCompetitionPersistSaveCount; ++save) {
        sCompetitionPersist.save[save].saveId = legacy->save[save].saveId;
        for (int world = 0; world < kCompetitionPersistWorldCount; ++world) {
            CompetitionWorldScore& dst =
                sCompetitionPersist.save[save].world[world];
            const LegacyMoonWorldScore& src = legacy->save[save].world[world];
            dst.moonScore[0] = src.score[0];
            dst.moonScore[1] = src.score[1];
            dst.moonWinner = src.winner;
        }
    }
    sCompetitionPersist.checksum = 0;
    sCompetitionPersist.checksum =
        CalcCompetitionPersistChecksum(sCompetitionPersist);
    return true;
}

static void LoadCompetitionScoresForActiveWorld() {
    sCompetitionPersistReady = false;
#if PATCH_0022_ENABLED
    sCompetitionPersistDirty = false;
    sCompetitionPersistDelayTicks = 0;
#endif
    sCompetitionPersistSaveIndex = -1;
    sCompetitionPersistWorldIndex = -1;
    sCompetitionPersistSaveId = 0;
    int64_t saveId = 0;
    int worldId = -1;
    if (!ResolveCompetitionPersistKey(&saveId, &worldId)) {
        Logging.Log("[OCoop] PATCH-0021 persistence load skipped invalid key save=0x%llx world=%d",
                    (unsigned long long)saveId, worldId);
        return;
    }

    static CompetitionPersistState stateA = {};
    static CompetitionPersistState stateB = {};
    const bool validA = ReadCompetitionPersist(kCompetitionPersistPathA, &stateA);
    const bool validB = ReadCompetitionPersist(kCompetitionPersistPathB, &stateB);
    const char* source = "new";
    bool migrated = false;
    if (validA && (!validB ||
        static_cast<int32_t>(stateA.generation - stateB.generation) > 0)) {
        sCompetitionPersist = stateA;
        source = "A";
    } else if (validB) {
        sCompetitionPersist = stateB;
        source = "B";
    } else {
        migrated = ImportLegacyMoonPersist(&source);
        if (!migrated)
            InitEmptyCompetitionPersist();
    }

    const int saveIndex = FindCompetitionSave(saveId, true);
    if (saveIndex < 0) {
        Logging.Log("[OCoop] PATCH-0021 persistence load failed save table full save=0x%llx",
                    (unsigned long long)saveId);
        return;
    }
    CompetitionWorldScore& score =
        sCompetitionPersist.save[saveIndex].world[worldId];
    sScores[0] = ClampDisplay(score.coinScore[0], kMaxDisplayScore);
    sScores[1] = ClampDisplay(score.coinScore[1], kMaxDisplayScore);
    sWinner = score.coinWinner >= -1 && score.coinWinner <= 1
        ? score.coinWinner : -1;
    sMoonScores[0] = ClampDisplay(score.moonScore[0], kMaxDisplayScore);
    sMoonScores[1] = ClampDisplay(score.moonScore[1], kMaxDisplayScore);
    sMoonWinner = score.moonWinner >= -1 && score.moonWinner <= 1
        ? score.moonWinner : -1;
    sCompetitionPersistReady = true;
    sCompetitionPersistSaveIndex = saveIndex;
    sCompetitionPersistWorldIndex = worldId;
    sCompetitionPersistSaveId = saveId;
    Logging.Log("[OCoop] PATCH-0021 persistence loaded source=%s gen=%u save=0x%llx world=%d coin=%d:%d coin-winner=%d moon=%d:%d moon-winner=%d",
                source, sCompetitionPersist.generation,
                (unsigned long long)saveId, worldId,
                sScores[0], sScores[1], sWinner,
                sMoonScores[0], sMoonScores[1], sMoonWinner);
    if (migrated) {
        const bool verified = SaveCompetitionScoresForActiveWorld();
        Logging.Log("[OCoop] PATCH-0021 legacy moon journal migrated source=%s verified=%d",
                    source, verified ? 1 : 0);
    }
}

static bool SaveCompetitionScoresForActiveWorld() {
    if (!sCompetitionPersistReady || sCompetitionPersistSaveIndex < 0 ||
        sCompetitionPersistWorldIndex < 0)
        return false;
#if PATCH_0023_ENABLED
    auto isDoneSaveDataSequence = OcoopFn<bool (*)()>(
        PatchOffsets::AlIsDoneSaveDataSequence);
    if (!isDoneSaveDataSequence()) {
        ++sCompetitionNativeSaveDeferrals;
        if (!sCompetitionNativeSaveBusy) {
            sCompetitionNativeSaveBusy = true;
            Logging.Log("[OCoop] PATCH-0023 persistence deferred: native save sequence busy");
        }
        return false;
    }
    if (sCompetitionNativeSaveBusy) {
        Logging.Log("[OCoop] PATCH-0023 persistence resumed after native save deferrals=%u",
                    sCompetitionNativeSaveDeferrals);
        sCompetitionNativeSaveBusy = false;
        sCompetitionNativeSaveDeferrals = 0;
    }
#endif
    CompetitionWorldScore& score = sCompetitionPersist
        .save[sCompetitionPersistSaveIndex].world[sCompetitionPersistWorldIndex];
    score.coinScore[0] = sScores[0];
    score.coinScore[1] = sScores[1];
    score.coinWinner = sWinner;
    score.moonScore[0] = sMoonScores[0];
    score.moonScore[1] = sMoonScores[1];
    score.moonWinner = sMoonWinner;
    ++sCompetitionPersist.generation;
    sCompetitionPersist.checksum = 0;
    sCompetitionPersist.checksum =
        CalcCompetitionPersistChecksum(sCompetitionPersist);
    const char* path = (sCompetitionPersist.generation & 1u) != 0
        ? kCompetitionPersistPathB : kCompetitionPersistPathA;
    const bool verified = WriteCompetitionPersist(path);
    Logging.Log("[OCoop] PATCH-0021 persistence write slot=%c gen=%u save=0x%llx world=%d coin=%d:%d moon=%d:%d verified=%d",
                path == kCompetitionPersistPathA ? 'A' : 'B',
                sCompetitionPersist.generation,
                (unsigned long long)sCompetitionPersistSaveId,
                sCompetitionPersistWorldIndex,
                sScores[0], sScores[1], sMoonScores[0], sMoonScores[1],
                verified ? 1 : 0);
    return verified;
}

#if PATCH_0022_ENABLED
static void MarkCompetitionPersistenceDirty() {
    if (!sCompetitionPersistReady)
        return;
    sCompetitionPersistDirty = true;
    sCompetitionPersistDelayTicks = kCompetitionPersistCoalesceTicks;
}

static bool FlushCompetitionPersistence(const char* reason) {
    if (!sCompetitionPersistDirty)
        return true;
    const bool verified = SaveCompetitionScoresForActiveWorld();
    if (verified) {
        sCompetitionPersistDirty = false;
        sCompetitionPersistDelayTicks = 0;
    } else {
        sCompetitionPersistDelayTicks = kCompetitionPersistCoalesceTicks;
    }
    Logging.Log("[OCoop] PATCH-0022 persistence flush reason=%s verified=%d dirty=%d",
                reason, verified ? 1 : 0,
                sCompetitionPersistDirty ? 1 : 0);
    return verified;
}

static void TickCompetitionPersistence() {
    if (!sCompetitionPersistDirty)
        return;
    if (sCompetitionPersistDelayTicks > 0) {
        --sCompetitionPersistDelayTicks;
        return;
    }
    FlushCompetitionPersistence("coalesced");
}

static void BeginRepeatMoonReward(int idx) {
    sRepeatMoonPlayer = idx;
    sRepeatMoonCoinsRemaining = kRepeatMoonCoinReward;
    sRepeatMoonRewardTicks = kRepeatMoonRewardTimeoutTicks;
    Logging.Log("[OCoop] PATCH-0022 repeat moon collector idx=%d expected-coins=%d moon-credit=0",
                idx, kRepeatMoonCoinReward);
}

static int ResolveCountUpPlayer(const void* coin) {
    if (sRepeatMoonPlayer >= 0 && sRepeatMoonPlayer <= 1 &&
        sRepeatMoonCoinsRemaining > 0 && sRepeatMoonRewardTicks > 0)
        return sRepeatMoonPlayer;
    return NearestPlayerIndex(coin);
}

static void ConsumeRepeatMoonCoins(int player, int amount) {
    if (player != sRepeatMoonPlayer || amount <= 0 ||
        sRepeatMoonCoinsRemaining <= 0)
        return;
    sRepeatMoonCoinsRemaining -= amount;
    if (sRepeatMoonCoinsRemaining > 0)
        return;
    Logging.Log("[OCoop] PATCH-0022 repeat moon reward complete idx=%d coins=%d",
                player, kRepeatMoonCoinReward);
    sRepeatMoonPlayer = -1;
    sRepeatMoonCoinsRemaining = 0;
    sRepeatMoonRewardTicks = 0;
}

static void TickRepeatMoonReward() {
    if (sRepeatMoonPlayer < 0 || sRepeatMoonCoinsRemaining <= 0)
        return;
    if (sRepeatMoonRewardTicks > 0) {
        --sRepeatMoonRewardTicks;
        return;
    }
    Logging.Log("[OCoop] PATCH-0022 repeat moon reward timeout idx=%d remaining=%d",
                sRepeatMoonPlayer, sRepeatMoonCoinsRemaining);
    sRepeatMoonPlayer = -1;
    sRepeatMoonCoinsRemaining = 0;
}
#endif

static void CreditMoon(int idx, int amount, const char* source) {
    if (!ocoop::config::Get().moonRaceEnabled || idx < 0 || idx > 1 ||
        amount < 1)
        return;
    if (!sCompetitionPersistReady)
        LoadCompetitionScoresForActiveWorld();
    int next = sMoonScores[idx] + amount;
    if (next > kMaxDisplayScore)
        next = kMaxDisplayScore;
    sMoonScores[idx] = next;
    if (sMoonWinner < 0 &&
        sMoonScores[idx] >= ocoop::config::Get().moonRaceTarget) {
        sMoonWinner = idx;
        Logging.Log("[OCoop] PATCH-0020 MOON WINNER p=%d score=%d:%d target=%d",
                    idx + 1, sMoonScores[0], sMoonScores[1],
                    ocoop::config::Get().moonRaceTarget);
    }
#if PATCH_0022_ENABLED
    MarkCompetitionPersistenceDirty();
    const bool persistenceQueued = sCompetitionPersistReady;
#else
    const bool persistenceQueued = SaveCompetitionScoresForActiveWorld();
#endif
    ApplyAll();
    Logging.Log("[OCoop] PATCH-0020 moon source=%s idx=%d amount=%d score=%d:%d world=%d persistence-queued=%d",
                source, idx, amount, sMoonScores[0], sMoonScores[1],
                sCompetitionPersistWorldIndex, persistenceQueued ? 1 : 0);
}
#endif
}  // namespace coinrace

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_022.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_023.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_058.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_060.inc"
#endif

#if PATCH_0028_ENABLED
HOOK_DEFINE_TRAMPOLINE(Patch0028BlockBrick2DCoin) {
    static bool Callback(void* block, const void* message,
                         void* other, void* selfSensor) {
        bool isPlayerUpperPunch = false;
        int idx = -1;
        int itemType = -1;
        void* singleItemState = nullptr;

        if (IsPtr8((uintptr_t)block) && IsPtr8((uintptr_t)message) &&
            IsPtr8((uintptr_t)other)) {
            auto isMsgPlayerUpperPunch2D =
                OcoopFn<bool (*)(const void*)>(PatchOffsets::RsIsMsgPlayerUpperPunch2D);
            isPlayerUpperPunch = isMsgPlayerUpperPunch2D(message);
            if (isPlayerUpperPunch) {
                idx = coinrace::ResolvePlayerIndex(block, other);
                itemType = *reinterpret_cast<const int*>((uintptr_t)block + 0x128);
                if (itemType >= 0 && itemType != 8)
                    singleItemState = *reinterpret_cast<void**>((uintptr_t)block + 0x120);
            }
        }

        const bool accepted = Orig(block, message, other, selfSensor);
        if (!accepted || !isPlayerUpperPunch || idx < 0)
            return accepted;

        bool repaired = false;
        if (IsPtr8((uintptr_t)singleItemState) && IsPtr8((uintptr_t)other)) {
            *reinterpret_cast<void**>((uintptr_t)singleItemState + 0x28) = other;
            repaired = true;
        }

        const bool credited = itemType == 1;
        if (credited)
            coinrace::Credit(idx, 1, "brick2d");

        static unsigned logged = 0;
        if (logged < 24) {
            ++logged;
            Logging.Log("[OCoop] PATCH-0028 BlockBrick2D accepted idx=%d itemType=%d state=%p attackerRepaired=%d coinCredit=%d",
                        idx, itemType, singleItemState,
                        repaired ? 1 : 0, credited ? 1 : 0);
        }
        return accepted;
    }
};
#endif

HOOK_DEFINE_TRAMPOLINE(Patch0019DirectCoin3D) {
    static bool Callback(void* receiver, void* sender) {
        bool accepted = Orig(receiver, sender);
        if (!accepted || !IsPtr8((uintptr_t)receiver) || !IsPtr8((uintptr_t)sender))
            return accepted;
        auto getSensorHost = OcoopFn<void* (*)(const void*)>(PatchOffsets::AlGetSensorHost);
        void* receiverHost = getSensorHost(receiver);
        int idx = coinrace::ResolvePlayerIndex(receiverHost, sender);
        if (idx >= 0) {
            coinrace::Credit(idx, 1, "direct3d");
        } else {
            coinrace::NoteIgnored("direct3d", sender);
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_024.inc"
#endif
        }
        return accepted;
    }
};

HOOK_DEFINE_TRAMPOLINE(Patch0019DirectCoin2D) {
    static bool Callback(void* coin, const void* message, void* other, void* selfSensor) {
        bool accepted = Orig(coin, message, other, selfSensor);
        if (!accepted || !IsPtr8((uintptr_t)coin) || !IsPtr8((uintptr_t)message) ||
            !IsPtr8((uintptr_t)other))
            return accepted;
        auto isMsgItemGet2D = OcoopFn<bool (*)(const void*)>(PatchOffsets::RsIsMsgItemGet2D);
        if (!isMsgItemGet2D(message))
            return accepted;
        int idx = coinrace::ResolvePlayerIndex(coin, other);
        if (idx >= 0) {
            coinrace::Credit(idx, 1, "direct2d");
        } else {
            coinrace::NoteIgnored("direct2d-family", other);
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_025.inc"
#endif
        }
        return accepted;
    }
};

/* Multi-coin/NPC rewards enter Coin::exeCountUp without a collector sensor.
 * Publish the nearest registered player only for this producer's dynamic
 * extent. The addCoin observer measures each actual native increment, so a
 * CountUpFive credits five without parsing nerve pointers. */
HOOK_DEFINE_TRAMPOLINE(Patch0019CoinCountUpScope) {
    static void Callback(void* coin) {
        const int previousPlayer = coinrace::sCountUpPlayer;
        const unsigned previousDepth = coinrace::sCountUpDepth;
#if PATCH_0022_ENABLED
        coinrace::sCountUpPlayer = coinrace::ResolveCountUpPlayer(coin);
#else
        coinrace::sCountUpPlayer = coinrace::NearestPlayerIndex(coin);
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_026.inc"
#endif
        coinrace::sCountUpDepth = previousDepth + 1;
        Orig(coin);
        coinrace::sCountUpDepth = previousDepth;
        coinrace::sCountUpPlayer = previousPlayer;
    }
};

HOOK_DEFINE_INLINE(Patch0019ScopedAddCoin) {
    static void Callback(exl::hook::InlineCtx* ctx) {
        const int amount = (int)ctx->W[1];
        if (coinrace::sCountUpDepth > 0 && coinrace::sCountUpPlayer >= 0) {
            coinrace::Credit(coinrace::sCountUpPlayer, amount, "countup3d");
#if PATCH_0022_ENABLED
            coinrace::ConsumeRepeatMoonCoins(coinrace::sCountUpPlayer, amount);
#endif
        }
    }
};

#if PATCH_0020_ENABLED
 
HOOK_DEFINE_TRAMPOLINE(Patch0020ShineCollector) {
    static bool Callback(void* shine, const void* message,
                         void* other, void* selfSensor) {
        bool get3d = false;
        bool get2d = false;
        bool wasAlreadyGot = false;
        int rewardAmount = 1;
        int shineType = -1;
        if (IsPtr8((uintptr_t)shine) && IsPtr8((uintptr_t)message)) {
            auto isShineGet =
                OcoopFn<bool (*)(const void*)>(PatchOffsets::RsIsMsgShineGet);
            auto isShineGet2D =
                OcoopFn<bool (*)(const void*)>(PatchOffsets::RsIsMsgShineGet2D);
            get3d = isShineGet(message);
            get2d = isShineGet2D(message);
#if PATCH_0022_ENABLED
            if (get3d || get2d) {
                auto isGot =
                    OcoopFn<bool (*)(const void*)>(PatchOffsets::ShineIsGot);
                wasAlreadyGot = isGot(shine);
            }
#endif
#if PATCH_0027_ENABLED
            if ((get3d || get2d) && !wasAlreadyGot) {
                shineType = *(const int*)((uintptr_t)shine + 0x1a0);
                if (shineType == 2)
                    rewardAmount = 3;
            }
#endif
        }
        bool accepted = Orig(shine, message, other, selfSensor);
        if (!accepted || !IsPtr8((uintptr_t)shine) ||
            !IsPtr8((uintptr_t)message) || !IsPtr8((uintptr_t)other))
            return accepted;
        if (!get3d && !get2d)
            return accepted;
        const int idx = coinrace::ResolvePlayerIndex(shine, other);
        if (idx >= 0) {
#if PATCH_0022_ENABLED
            if (wasAlreadyGot) {
                coinrace::BeginRepeatMoonReward(idx);
                return accepted;
            }
#endif
#if PATCH_0027_ENABLED
            static unsigned cardinalityLogCount = 0;
            if (cardinalityLogCount < 12) {
                ++cardinalityLogCount;
                Logging.Log("[OCoop] PATCH-0027 moon cardinality type=%d amount=%d kind=%s idx=%d",
                            shineType, rewardAmount,
                            get2d ? "2d" : "3d", idx);
            }
#endif
            coinrace::CreditMoon(idx, rewardAmount,
                                 get2d ? "direct2d" : "direct3d");
        } else {
            Logging.Log("[OCoop] PATCH-0020 moon ignored kind=%s reason=no-registered-player",
                        get2d ? "2d" : "3d");
        }
        return accepted;
    }
};
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_027.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_028.inc"
#endif
#endif

/* StageSceneLayout C1: (this, name, LayoutInitInfo&, PlayerHolder*,
 * SubCameraRenderer*), verified by file_list.yml and Ghidra. */
HOOK_DEFINE_TRAMPOLINE(Patch0014P2HudLayoutCtor) {
    static void Callback(void* self, const char* name, const void* layoutInitInfo,
                         const void* playerHolder, const void* subCameraRenderer) {
        Orig(self, name, layoutInitInfo, playerHolder, subCameraRenderer);
        /* Reload before constructing OCoop's scene-owned HUD. All later scene
         * systems (P2 creation, camera, bubble, respawn) consume this same
         * immutable settings snapshot. */
        ocoop::config::Reload();
        p2hud::Create(self, layoutInitInfo);
        p2hud::Appear(self);
#if PATCH_0019_ENABLED
        coinrace::Create(self, layoutInitInfo);
#endif
    }
};
HOOK_DEFINE_TRAMPOLINE(Patch0014P2HudLayoutEnd) {
    static void Callback(void* self) {
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_029.inc"
#endif
#if PATCH_0019_ENABLED
        coinrace::End(self);
#endif
        p2hud::End(self);
        Orig(self);
    }
};
/* StageSceneLayout::start @ 0x20ca20 — the native post-demo HUD restore
 * boundary (also runs at normal scene start, where the isActive gate makes
 * OnLayoutStart a no-op). */
HOOK_DEFINE_TRAMPOLINE(Patch0014P2HudLayoutStart) {
    static void Callback(void* self) {
        Orig(self);
        p2hud::OnLayoutStart(self);
#if PATCH_0019_ENABLED
        coinrace::OnLayoutStart(self);
#endif
    }
};

#if PATCH_0024_ENABLED
/* DemoChangeWorldScene::exeTalk entry @ 0x4a7070. The callback only compares
 * cached pointer values and clears them; it never dereferences the retiring
 * scene. The pointer-presence edge makes this one-shot per world transition,
 * while a later StageSceneLayout ctor naturally arms the next transition. */
HOOK_DEFINE_INLINE(Patch0024ChangeWorldDetach) {
    static void Callback(exl::hook::InlineCtx*) {
        bool hadP2Hud = false;
        bool hadCompetitionHud = false;
#if PATCH_0014_ENABLED
        hadP2Hud = p2hud::sCounter != nullptr || p2hud::sOwner != nullptr;
#endif
#if PATCH_0019_ENABLED
        hadCompetitionHud = coinrace::sHud != nullptr || coinrace::sOwner != nullptr;
#endif
        if (!hadP2Hud && !hadCompetitionHud)
            return;
#if PATCH_0014_ENABLED
        p2hud::DetachForSceneReset();
#endif
#if PATCH_0019_ENABLED
        coinrace::DetachForSceneReset();
#endif
        Logging.Log("[OCoop] PATCH-0024 change-world detach p2hud=%d competition=%d",
                    hadP2Hud ? 1 : 0, hadCompetitionHud ? 1 : 0);
    }
};
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_030.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_031.inc"
#endif
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_032.inc"
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_033.inc"
#endif

#if PATCH_0007_ENABLED
namespace patch0007 {
    static float sTargetFactor = 1.0f;
    static float sAppliedFactor = 1.0f;
    static float sSeparation = -1.0f;
    static unsigned sFreshRawCalls = 0;

    static void ObserveHorizontalSeparation(float dx, float dz) {
        float separation = __builtin_sqrtf(dx * dx + dz * dz);
        if (!(separation >= 0.0f) || separation > 100000.0f)
            return;

        float t = (separation - PATCH_0007_SEP_START) /
                  (PATCH_0007_SEP_FULL - PATCH_0007_SEP_START);
        if (t < 0.0f)
            t = 0.0f;
        else if (t > 1.0f)
            t = 1.0f;

        sSeparation = separation;
        sTargetFactor = PATCH_0007_BASE_ZOOM +
                        t * (PATCH_0007_MAX_ZOOM - PATCH_0007_BASE_ZOOM);
        /* Scalar snapshot only: refreshed by PATCH-0004 from live actor poses.
         * If the player-target path stops, raw calls fade smoothly to vanilla. */
        sFreshRawCalls = 180;
    }

    static float ScaleRawDistance(float distance, void* poser) {
        if (!(distance > 0.0f) || distance > 1000000.0f)
            return distance;

        if (sFreshRawCalls > 0)
            --sFreshRawCalls;
        else {
            sTargetFactor = 1.0f;
            sSeparation = -1.0f;
        }

        sAppliedFactor += (sTargetFactor - sAppliedFactor) * PATCH_0007_LERP;
        if (sAppliedFactor < 1.0f)
            sAppliedFactor = 1.0f;
        else if (sAppliedFactor > PATCH_0007_MAX_ZOOM)
            sAppliedFactor = PATCH_0007_MAX_ZOOM;

        static unsigned calls = 0;
        static unsigned logged = 0;
        if ((calls++ % 120) == 0 && logged < 40) {
            logged++;
            Logging.Log("[OCoop] PATCH-0007 zoom poser=%p raw=%.0f sep=%.0f target=%.2f applied=%.2f out=%.0f",
                        poser, distance, sSeparation, sTargetFactor, sAppliedFactor,
                        distance * sAppliedFactor);
        }
        return distance * sAppliedFactor;
    }
}
#endif

#if PATCH_0008_ENABLED
namespace patch0008 {
    static float sTargetFactor = 1.0f;
    static float sAppliedFactor = 1.0f;
    static float sSeparation = -1.0f;
    static unsigned sFreshPoseCalls = 0;

    static float BaseZoom() { return ocoop::config::Get().cameraBaseZoom; }
    static float MaxZoom() { return ocoop::config::Get().cameraMaxZoom; }
    static float SeparationStart() { return ocoop::config::Get().cameraSeparationStart; }
    static float SeparationFull() { return ocoop::config::Get().cameraSeparationFull; }
    static float Lerp() { return ocoop::config::Get().cameraLerp; }

    static void ObserveHorizontalSeparation(float dx, float dz) {
        float separation = __builtin_sqrtf(dx * dx + dz * dz);
        if (!(separation >= 0.0f) || separation > 100000.0f)
            return;

        const auto& settings = ocoop::config::Get();
        float t = (separation - settings.cameraSeparationStart) /
                  (settings.cameraSeparationFull - settings.cameraSeparationStart);
        if (t < 0.0f)
            t = 0.0f;
        else if (t > 1.0f)
            t = 1.0f;

        sSeparation = separation;
        sTargetFactor = settings.cameraBaseZoom +
                        t * (settings.cameraMaxZoom - settings.cameraBaseZoom);
        /* A scalar snapshot only: if player-target observation stops, final
         * pose scaling fades safely back to Odyssey's unmodified camera. */
        sFreshPoseCalls = 180;
    }

    static void ScaleFinalPose(float* eye, const float* at, void* poser) {
        if (eye == nullptr || at == nullptr)
            return;

        if (sFreshPoseCalls > 0)
            --sFreshPoseCalls;
        else {
            sTargetFactor = 1.0f;
            sSeparation = -1.0f;
        }

        const auto& settings = ocoop::config::Get();
        sAppliedFactor += (sTargetFactor - sAppliedFactor) * settings.cameraLerp;
        if (sAppliedFactor < 1.0f)
            sAppliedFactor = 1.0f;
        else if (sAppliedFactor > settings.cameraMaxZoom)
            sAppliedFactor = settings.cameraMaxZoom;

        float dx = eye[0] - at[0];
        float dy = eye[1] - at[1];
        float dz = eye[2] - at[2];
        float before = __builtin_sqrtf(dx * dx + dy * dy + dz * dz);
        if (!(before > 0.0f) || before > 1000000.0f)
            return;

        eye[0] = at[0] + dx * sAppliedFactor;
        eye[1] = at[1] + dy * sAppliedFactor;
        eye[2] = at[2] + dz * sAppliedFactor;

        static unsigned calls = 0;
        static unsigned logged = 0;
        if ((calls++ % 120) == 0 && logged < 40) {
            logged++;
            Logging.Log("[OCoop] PATCH-0008 zoom final poser=%p sep=%.0f target=%.2f applied=%.2f d=%.0f->%.0f",
                        poser, sSeparation, sTargetFactor, sAppliedFactor,
                        before, before * sAppliedFactor);
        }
    }
}
#endif

#if PATCH_0009_ENABLED
namespace patch0009 {
    static int sP2Health = PATCH_0009_P2_HEALTH_MAX;
    static int sP2MaxHealth = PATCH_0009_P2_HEALTH_MAX;
    static bool sP2HealthValid = false;
    static bool sP1Terminal = false;
    static bool sP1DelayActive = false;
    static unsigned sP1DownFrames = 0;
    static bool sP1DeadStateSeen = false;
    static bool sP2Terminal = false;
    static bool sP2DelayActive = false;
    static unsigned sP2DownFrames = 0;
    static bool sP2DeadStateSeen = false;

    static uintptr_t GetGameDataHolder(void* actor) {
        uintptr_t player = (uintptr_t)actor;
        if (!IsPtr8(player))
            return 0;
        uintptr_t holder = 0;
        auto makeAccessor = OcoopFn<void (*)(void*, const void*)>(
            PatchOffsets::GameDataHolderAccessorCtor);
        /* PlayerDamageKeeper uses the same proven IUseSceneObjHolder +0x20. */
        makeAccessor(&holder, (const void*)(player + 0x20));
        return IsPtr8(holder) ? holder : 0;
    }

    static int ReadNativeMaxHealth(void* actor) {
        uintptr_t holder = GetGameDataHolder(actor);
        if (!IsPtr8(holder))
            return PATCH_0009_P2_HEALTH_MAX;
        auto getMax = OcoopFn<int (*)(uintptr_t)>(
            PatchOffsets::GameDataGetPlayerHitPointMaxCurrent);
        int maxHealth = getMax(holder);
        if (maxHealth < PATCH_0009_P2_HEALTH_MAX)
            maxHealth = PATCH_0009_P2_HEALTH_MAX;
        if (maxHealth > 6)
            maxHealth = 6;
        return maxHealth;
    }

    static void ResetP2Health(void* actor) {
        sP2MaxHealth = ReadNativeMaxHealth(actor);
        sP2Health = sP2MaxHealth;
        sP2HealthValid = true;
#if PATCH_0014_ENABLED
        p2hud::NotifyHealth(sP2Health, sP2MaxHealth);
#endif
    }

    static void ResetSceneHealthState(void* p2) {
#if PATCH_0014_ENABLED
        p2hud::DetachForSceneReset();
#endif
        sP1Terminal = false;
        sP1DelayActive = false;
        sP1DownFrames = 0;
        sP1DeadStateSeen = false;
        sP2Terminal = false;
        sP2DelayActive = false;
        sP2DownFrames = 0;
        sP2DeadStateSeen = false;
        ResetP2Health(p2);
    }

    static void GrantP2LifeUp() {
        int oldMax = sP2MaxHealth;
        sP2MaxHealth = 6;
        if (!sP2Terminal)
            sP2Health = sP2MaxHealth;
        sP2HealthValid = true;
#if PATCH_0014_ENABLED
        p2hud::NotifyHealth(sP2Health, sP2MaxHealth);
#endif
        Logging.Log("[OCoop] PATCH-0009 p2 Life-Up event %d->%d hp=%d",
                    oldMax, sP2MaxHealth, sP2Health);
    }

     
    static void HealP2Full(const char* route, bool touchHud) {
        if (!sP2HealthValid || sP2Terminal)
            return;
        int before = sP2Health;
        sP2Health = sP2MaxHealth;
#if PATCH_0014_ENABLED
        if (touchHud)
            p2hud::NotifyHealth(sP2Health, sP2MaxHealth);
#endif
        Logging.Log("[OCoop] PATCH-0009 moon-heal route=%s p2 %d->%d/%d hud=%d",
                    route, before, sP2Health, sP2MaxHealth, touchHud ? 1 : 0);
    }

    static bool IsP2(void* actor) {
        if (!IsPtr8((uintptr_t)actor))
            return false;
        auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
        return getPlayerActor(actor, 1) == actor;
    }

    static bool IsP1(void* actor) {
        if (!IsPtr8((uintptr_t)actor))
            return false;
        auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
        return getPlayerActor(actor, 0) == actor;
    }

#if PATCH_0018_ENABLED
    static bool IsP2AtLastPrivateHeart(void* actor) {
        return sP2HealthValid && !sP2Terminal && sP2Health == 1 &&
               IsP2(actor);
    }
#endif

    static bool StartPlayerRecovery(void* actor, const char* reason,
                                    bool restoreGlobalHealth) {
        uintptr_t player = (uintptr_t)actor;
        if (!IsPtr8(player))
            return false;

        auto isNerve = OcoopFn<bool (*)(const void*, const void*)>(PatchOffsets::AlIsNerve);
        const void* nrvAbyss =
            (const void*)exl::util::modules::GetTargetOffset(PatchOffsets::NrvPlayerActorHakoniwaAbyss);
        if (isNerve(actor, nrvAbyss))
            return true;

        uintptr_t recovery = *(uintptr_t*)(player + 0x270);
        auto recoveryIsValid = OcoopFn<bool (*)(void*)>(PatchOffsets::RecoveryIsValid);
        if (!IsPtr8(recovery) || !recoveryIsValid((void*)recovery)) {
            Logging.Log("[OCoop] PATCH-0009 p2 recovery skip reason=%s recovery=%p",
                        reason, (void*)recovery);
            return false;
        }

        uintptr_t hackCap = *(uintptr_t*)(player + 0x148);
        uintptr_t bindKeeper = *(uintptr_t*)(player + 0x1f0);
        uintptr_t carryKeeper = *(uintptr_t*)(player + 0x1f8);
        uintptr_t equipUser = *(uintptr_t*)(player + 0x200);
        uintptr_t stateAbyss = *(uintptr_t*)(player + 0x3b8);
        if (!IsPtr8(hackCap) || !IsPtr8(bindKeeper) || !IsPtr8(carryKeeper) ||
            !IsPtr8(equipUser) || !IsPtr8(stateAbyss)) {
            Logging.Log("[OCoop] PATCH-0009 p2 recovery bad fields reason=%s cap=%p bind=%p carry=%p equip=%p abyss=%p",
                        reason, (void*)hackCap, (void*)bindKeeper, (void*)carryKeeper,
                        (void*)equipUser, (void*)stateAbyss);
            return false;
        }

        if (restoreGlobalHealth) {
            uintptr_t holder = GetGameDataHolder(actor);
            if (!IsPtr8(holder)) {
                Logging.Log("[OCoop] PATCH-0010 p1 recovery missing gameData actor=%p",
                            actor);
                return false;
            }
            auto recoverMax = OcoopFn<void (*)(const void*)>(
                PatchOffsets::GameDataRecoveryPlayerMaxForSystem);
            recoverMax((const void*)holder);
        }

        auto forceRecovery = OcoopFn<void (*)(void*, void*, void*, void*, void*, void*)>(
            PatchOffsets::PlayerForceRecoveryHelper);
        forceRecovery(actor, (void*)hackCap, (void*)carryKeeper,
                      (void*)bindKeeper, (void*)equipUser, (void*)stateAbyss);
        Logging.Log("[OCoop] PATCH-0010 p%d recovery start reason=%s actor=%p",
                    IsP2(actor) ? 2 : 1, reason, actor);
        return true;
    }

#if PATCH_0010_ENABLED
    static void BeginP1Terminal(void* actor, const char* reason) {
        if (sP1Terminal)
            return;
        sP1Terminal = true;
        sP1DelayActive = false;
        sP1DownFrames = 0;
        sP1DeadStateSeen = false;
        Logging.Log("[OCoop] PATCH-0010 p1 terminal begin reason=%s actor=%p",
                    reason, actor);
    }

    static void BeginP2Terminal(void* actor, const char* reason) {
        if (sP2Terminal)
            return;
        sP2Terminal = true;
        sP2DelayActive = false;
        sP2DownFrames = 0;
        sP2DeadStateSeen = false;
        Logging.Log("[OCoop] PATCH-0010 p2 terminal begin reason=%s actor=%p hp=%d",
                    reason, actor, sP2Health);
    }

#if PATCH_0018_ENABLED
    /* The native pre-movement last-heart branch calls dead(), not
     * damageForce(). Mirror its terminal health transition into the private
     * P2 sidecar before suppressing the shared GameData kill in the existing
     * Patch0009P2Dead trampoline. */
    static void BeginP2TerminalFromDead(void* actor, const char* reason) {
        if (sP2Terminal)
            return;
        if (!sP2HealthValid)
            ResetP2Health(actor);
        int before = sP2Health;
        sP2Health = 0;
#if PATCH_0014_ENABLED
        p2hud::NotifyHealth(sP2Health, sP2MaxHealth);
#endif
        Logging.Log("[OCoop] PATCH-0018 p2 direct-dead hp=%d->0 reason=%s actor=%p",
                    before, reason, actor);
        BeginP2Terminal(actor, reason);
    }
#endif

    static void NoteDeadState(void* state, bool animationEnded) {
        uintptr_t self = (uintptr_t)state;
        void* actor = IsPtr8(self) ? *(void**)(self + 0x18) : nullptr;
        if (sP1Terminal && IsP1(actor)) {
            if (!sP1DeadStateSeen) {
                sP1DeadStateSeen = true;
                Logging.Log("[OCoop] PATCH-0010 p1 native dead-state entered state=%p actor=%p",
                            state, actor);
            }
            if (animationEnded && !sP1DelayActive) {
                sP1DelayActive = true;
                sP1DownFrames = 0;
                Logging.Log("[OCoop] PATCH-0010 p1 native death complete; delayed respawn starts seconds=%.2f frames=%u",
                            ocoop::config::Get().respawnDelaySeconds,
                            ocoop::config::RespawnDelayFrames());
            }
        } else if (sP2Terminal && IsP2(actor)) {
            if (!sP2DeadStateSeen) {
                sP2DeadStateSeen = true;
                Logging.Log("[OCoop] PATCH-0010 p2 native dead-state entered state=%p actor=%p",
                            state, actor);
            }
            if (animationEnded && !sP2DelayActive) {
                sP2DelayActive = true;
                sP2DownFrames = 0;
                Logging.Log("[OCoop] PATCH-0010 p2 native death complete; delayed respawn starts seconds=%.2f frames=%u",
                            ocoop::config::Get().respawnDelaySeconds,
                            ocoop::config::RespawnDelayFrames());
            }
        }
    }

    /* Called from the already-installed per-player control hook. It receives a
     * live actor every call and never keeps a scene heap pointer across frames. */
    static void TickTerminal(void* actor) {
        const unsigned downFrames = ocoop::config::RespawnDelayFrames();
        bool p1 = IsP1(actor);
        bool p2 = !p1 && IsP2(actor);
        if (!p1 && !p2)
            return;

        if (p1 && sP1Terminal && sP1DelayActive) {
            ++sP1DownFrames;
            if (sP1DownFrames % PATCH_0010_GAME_TICKS_PER_SECOND == 0 &&
                sP1DownFrames < downFrames) {
                Logging.Log("[OCoop] PATCH-0010 p1 delayed respawn %u/%u",
                            sP1DownFrames, downFrames);
            }
            if (sP1DownFrames < downFrames)
                return;
            if (!StartPlayerRecovery(actor, "tunable-delay-respawn", true)) {
                sP1DownFrames = downFrames > PATCH_0010_GAME_TICKS_PER_SECOND
                                    ? downFrames - PATCH_0010_GAME_TICKS_PER_SECOND
                                    : 0;
                Logging.Log("[OCoop] PATCH-0010 p1 delayed respawn retry pending");
                return;
            }
            sP1Terminal = false;
            sP1DelayActive = false;
            sP1DeadStateSeen = false;
            Logging.Log("[OCoop] PATCH-0010 p1 respawn recovery started; native health restored");
            return;
        }

        if (p2 && sP2Terminal && sP2DelayActive) {
            ++sP2DownFrames;
            if (sP2DownFrames % PATCH_0010_GAME_TICKS_PER_SECOND == 0 &&
                sP2DownFrames < downFrames) {
                Logging.Log("[OCoop] PATCH-0010 p2 delayed respawn %u/%u",
                            sP2DownFrames, downFrames);
            }
            if (sP2DownFrames < downFrames)
                return;
            if (!StartPlayerRecovery(actor, "tunable-delay-respawn", false)) {
                sP2DownFrames = downFrames > PATCH_0010_GAME_TICKS_PER_SECOND
                                    ? downFrames - PATCH_0010_GAME_TICKS_PER_SECOND
                                    : 0;
                Logging.Log("[OCoop] PATCH-0010 p2 delayed respawn retry pending");
                return;
            }
            sP2Terminal = false;
            sP2DelayActive = false;
            sP2DeadStateSeen = false;
            ResetP2Health(actor);
            Logging.Log("[OCoop] PATCH-0010 p2 respawn recovery started; health reset=%d max=%d",
                        sP2Health, sP2MaxHealth);
        }
    }
#endif
    /* Reproduces the matching PlayerDamageKeeper local bookkeeping, excluding
     * only its shared GameDataFunction::damagePlayer write. Fields are proven
     * by Ghidra 20260710-082838: actor +0x00, invalid +0x10/+0x14,
     * prevent +0x1c, kids-mode cache +0x24/+0x28/+0x2c. */
    static bool HandleDamage(void* keeper, int damageInvalid, bool force
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_034.inc"
#endif
    ) {
        uintptr_t self = (uintptr_t)keeper;
        if (!IsPtr8(self))
            return false;
        void* actor = *(void**)self;
        if (!IsP2(actor))
            return false;

        *(unsigned char*)(self + 0x10) = 1;
        *(int*)(self + 0x14) = damageInvalid;
        if (!force && *(unsigned char*)(self + 0x1c) != 0)
            return true;

        if (!sP2HealthValid)
            ResetP2Health(actor);
        if (sP2Terminal)
            return true;
        int before = sP2Health;
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_035.inc"
#endif
        if (sP2Health > 0)
            --sP2Health;
        if (sP2MaxHealth > PATCH_0009_P2_HEALTH_MAX &&
            sP2Health <= PATCH_0009_P2_HEALTH_MAX) {
            sP2MaxHealth = PATCH_0009_P2_HEALTH_MAX;
            Logging.Log("[OCoop] PATCH-0009 p2 bonus tier consumed; max=%d hp=%d",
                        sP2MaxHealth, sP2Health);
        }

        *(int*)(self + 0x24) = sP2Health;
        *(int*)(self + 0x28) = 0;
        if (*(int*)(self + 0x2c) < 120)
            *(int*)(self + 0x2c) = 0;
#if PATCH_0014_ENABLED
        p2hud::NotifyHealth(sP2Health, sP2MaxHealth);
#endif

        Logging.Log("[OCoop] PATCH-0009 p2 %s hp=%d->%d actor=%p",
                    force ? "damageForce" : "damage", before, sP2Health, actor);
        if (sP2Health == 0) {
#if PATCH_0010_ENABLED
            BeginP2Terminal(actor, force ? "damageForce-zero" : "damage-zero");
#else
            if (StartPlayerRecovery(actor, "health-zero", false)) {
                ResetP2Health(actor);
                Logging.Log("[OCoop] PATCH-0009 p2 health reset=%d after recovery start",
                            sP2Health);
            } else {
                /* Keep P2 at one heart if recovery cannot safely start; this
                 * avoids converting an uncertain edge case into global death. */
                sP2Health = 1;
                *(int*)(self + 0x24) = sP2Health;
            }
#endif
        }
        return true;
    }
}
#endif

/* char* fields need no alignment; statically known to be C strings
 * (rs::getInitPlayerModelName / getInitCapTypeName read them as such). */
static bool IsStrPtr(uintptr_t p) {
    return p > 0x10000 && p < 0x8000000000UL;
}

#if PATCH_0001_ENABLED
namespace patch0001 {
     
    static bool sCaptureValid = false;
    static uintptr_t sActorInitInfo = 0;
    alignas(16) static unsigned char sPiiCopy[0x48];

    template <typename T>
    static T fn(ptrdiff_t nso) {
        return reinterpret_cast<T>(exl::util::modules::GetTargetOffset(nso));
    }
}

/* Hook A: the `blr x8` that virtually calls P1's initPlayer. Register-indirect
 * branch — relocation-safe (the never-hook rule is about PC-relative `bl`).
 * Runs BEFORE the call: x1=&ActorInitInfo, x2=&PlayerInitInfo, both stack-live. */
HOOK_DEFINE_INLINE(Patch0001CaptureInitInfo) {
    static void Callback(exl::hook::InlineCtx* ctx) {
        /* Keep the confirmed early reload boundary: StageSceneLayout is not
         * constructed until BL 0x4ca55c, after P2 spawn at 0x4c9fd8. Costume
         * settings must therefore load here; the later layout reload makes HUD
         * placement consume the same file for the new scene. */
        ocoop::config::Reload();
        patch0001::sCaptureValid = false;
        uintptr_t aii = ctx->X[1];
        uintptr_t pii = ctx->X[2];
        if (!IsPtr8(aii) || !IsPtr8(pii)) {
            Logging.Log("[OCoop] PATCH-0001 A: pointer guard failed aii=%p pii=%p",
                        (void*)aii, (void*)pii);
            return;
        }
        for (unsigned i = 0; i < sizeof(patch0001::sPiiCopy); i++)
            patch0001::sPiiCopy[i] = ((unsigned char*)pii)[i];
        patch0001::sActorInitInfo = aii;
        patch0001::sCaptureValid = true;
        Logging.Log("[OCoop] PATCH-0001 A: captured aii=%p p1port=%d",
                    (void*)aii, *(int*)(pii + 0x10));
    }
};

/* Hook B: first instruction after P1's registerPlayer (`orr w0,wzr,#0x30`,
 * verified not PC-relative). StageScene::init's frame — and with it the
 * captured ActorInitInfo — is still live here. Replays P1's construction
 * recipe for P2 with only the controller port changed. */
HOOK_DEFINE_INLINE(Patch0001SpawnP2) {
    static void Callback(exl::hook::InlineCtx* ctx) {
        if (!patch0001::sCaptureValid) {
            Logging.Log("[OCoop] PATCH-0001 B: no capture, skip");
            return;
        }
        patch0001::sCaptureValid = false;  // one spawn per capture

        auto getPlayerControllerPort =
            patch0001::fn<int (*)(int)>(PatchOffsets::AlGetPlayerControllerPort);
        auto isPadConnected =
            patch0001::fn<bool (*)(int)>(PatchOffsets::AlIsPadConnected);
        auto getDisplayName =
            patch0001::fn<void (*)(const char**, const void*)>(PatchOffsets::AlGetDisplayName);
        auto createPlayer =
            patch0001::fn<void* (*)(const char*)>(PatchOffsets::CreatePlayerFunctionHakoniwa);
        auto createPadRumbleKeeper =
            patch0001::fn<void* (*)(const void*, int)>(PatchOffsets::AlCreatePadRumbleKeeper);
        auto registerPlayer =
            patch0001::fn<void (*)(void*, void*)>(PatchOffsets::AlPlayerFunctionRegisterPlayer);

        int p1port = *(int*)(patch0001::sPiiCopy + 0x10);
        int p2port = getPlayerControllerPort(1);
        if (p2port < 0) {
            Logging.Log("[OCoop] PATCH-0001 B: no second Npad (p2port=%d) — "
                        "configure two controllers; skip", p2port);
            return;
        }
        if (p2port == p1port) {
            Logging.Log("[OCoop] PATCH-0001 B: p2port==p1port==%d, skip", p2port);
            return;
        }
        bool connected = isPadConnected(p2port);  // p2port >= 0 guaranteed above

        const char* name = nullptr;
        getDisplayName(&name, (const void*)patch0001::sActorInitInfo);
        if (!IsStrPtr((uintptr_t)name)) {
            Logging.Log("[OCoop] PATCH-0001 B: bad display name %p, skip", (const void*)name);
            return;
        }
        Logging.Log("[OCoop] PATCH-0001 B: p1port=%d p2port=%d connected=%d name=\"%s\"",
                    p1port, p2port, (int)connected, name);

        void* p2 = createPlayer(name);
        if (!IsPtr8((uintptr_t)p2)) {
            Logging.Log("[OCoop] PATCH-0001 B: createPlayer failed %p", p2);
            return;
        }
        Logging.Log("[OCoop] PATCH-0001 B: P2 constructed %p", p2);

        *(int*)(patch0001::sPiiCopy + 0x10) = p2port;

#if PATCH_0001_P2_COSTUME_ENABLED
        /* Override P2's body/cap model names (PlayerInitInfo +0x18/+0x20).
         * getInitPlayerModelName/getInitCapTypeName return these pointers
         * verbatim; the init worker loads ObjectData/<name> on demand. The
         * settings arrays live in this module's static storage, so the pointers
         * stay valid for the whole synchronous init. Empty string = leave the
         * corresponding P1 model pointer unchanged. */
        {
            const auto& settings = ocoop::config::Get();
            if (settings.p2Body[0] != '\0')
                *(const char**)(patch0001::sPiiCopy + 0x18) = settings.p2Body;
            if (settings.p2Cap[0] != '\0')
                *(const char**)(patch0001::sPiiCopy + 0x20) = settings.p2Cap;
            Logging.Log("[OCoop] PATCH-0001 B: P2 costume body=\"%s\" cap=\"%s\"",
                        *(const char**)(patch0001::sPiiCopy + 0x18),
                        *(const char**)(patch0001::sPiiCopy + 0x20));
        }
#endif

        uintptr_t vt = *(uintptr_t*)p2;
        if (!IsPtr8(vt)) {
            Logging.Log("[OCoop] PATCH-0001 B: bad P2 vtable %p", (void*)vt);
            return;
        }
        auto initPlayer = reinterpret_cast<void (*)(void*, const void*, const void*)>(
            *(uintptr_t*)(vt + 0xe0));
        initPlayer(p2, (const void*)patch0001::sActorInitInfo, patch0001::sPiiCopy);
        Logging.Log("[OCoop] PATCH-0001 B: P2 initPlayer done");

        void* keeper = createPadRumbleKeeper(p2, p2port);
        registerPlayer(p2, keeper);
        Logging.Log("[OCoop] PATCH-0001 B: P2 registered port=%d keeper=%p", p2port, keeper);
#if PATCH_0019_ENABLED && PATCH_0014_ENABLED
        coinrace::ResetRound();
#endif
#if PATCH_0009_ENABLED
        patch0009::ResetSceneHealthState(p2);
        Logging.Log("[OCoop] PATCH-0009 p2 health initialized=%d max=%d",
                    patch0009::sP2Health, patch0009::sP2MaxHealth);
#endif
         

#if PATCH_0005_ENABLED
        /* De-aggregate the pads: in single-play mode the first NpadController
         * has index mode -1 (= reads ANY pad), so P2's controller also drove
         * P1. changeMultiPlayMode(gps, 2, 2) pins pad i -> player i — the same
         * call native 2P mode makes. gps = al::GamePadSystem* captured at
         * PlayerInitInfo+0x00 (hook A); only reached when a second Npad exists
         * (guards above), so solo play keeps vanilla any-pad input. */
        uintptr_t gps = *(uintptr_t*)(patch0001::sPiiCopy + 0x00);
        if (IsPtr8(gps)) {
            auto changeMultiPlayMode =
                patch0001::fn<void (*)(void*, int, int)>(PatchOffsets::GamePadSystemChangeMultiPlayMode);
            changeMultiPlayMode((void*)gps, 2, 2);
            Logging.Log("[OCoop] PATCH-0005 multi-play pad mode set (gps=%p, pads pinned 0->P1, 1->P2)",
                        (void*)gps);
        } else {
            Logging.Log("[OCoop] PATCH-0005 bad GamePadSystem ptr %p, skip", (void*)gps);
        }
#endif
    }
};
#endif

#if PATCH_0002_ENABLED
/* Trampoline on PlayerRecoverySafetyPoint::isValid() const @ 0x460c90.
 * self (x0) = PlayerRecoverySafetyPoint*; mActor is its first member (+0x00 —
 * no vtable, sizeof 0xb8), mSafety3D.hasSafety is a byte at self+0x40 (per the
 * Ghidra decompile of isValid). We force the ENABLE gate on but keep the
 * hasSafety requirement: return orig || hasSafety3D. That makes a fall bubble-
 * recover only after the player has recorded a safe point (stood on ground) —
 * so no recover-to-origin and no spawn-time effect. Applies to both players.
 * Per-player log-on-change (max 2 actors tracked) confirms which players'
 * recovery path is queried (i.e. that P2 ticks the abyss/recovery state). */
HOOK_DEFINE_TRAMPOLINE(Patch0002ForceRecovery) {
    static bool Callback(void* self) {
        bool orig = Orig(self);

        uintptr_t s = (uintptr_t)self;
        uintptr_t actor = IsPtr8(s) ? *(uintptr_t*)s : 0;
        int port = IsPtr8(actor) ? *(int*)(actor + 0x118) : -1;
        bool hasSafety3D = IsPtr8(s) ? (*(unsigned char*)(s + 0x40) != 0) : false;
        bool forced = orig || hasSafety3D;

#if PATCH_0018_ENABLED && PATCH_0009_ENABLED && PATCH_0010_ENABLED
        /* executePreMovementNerveChange asks isValid at 0x41feb4, then asks
         * stock isPlayerHitPointOne. That stock helper sees shared P1 health,
         * not the P2 sidecar; with a false result it calls damageForce and
         * immediately tail-calls forceRecovery (0x420018), overwriting the
         * terminal route. At P2's private last heart, return false ONLY to this
         * caller. Native control then takes its adjacent dead() branch, which
         * Patch0009P2Dead already isolates from shared GameData health. */
        const uintptr_t base =
            (uintptr_t)exl::util::modules::GetTargetOffset(0);
        const uintptr_t lr = (uintptr_t)__builtin_return_address(0);
        const uintptr_t callerNso = lr >= base ? lr - base : 0;
        if (callerNso ==
                (uintptr_t)PatchOffsets::PreMovementRecoveryIsValidReturn &&
            patch0009::IsP2AtLastPrivateHeart((void*)actor)) {
            forced = false;
            Logging.Log("[OCoop] PATCH-0018 pre-movement last-heart selector actor=%p port=%d orig=%d hasSafety=%d -> recoveryValid=0",
                        (void*)actor, port, (int)orig, (int)hasSafety3D);
        }
#endif

        static uintptr_t sActors[2] = {0, 0};
        static int sLast[2] = {-2, -2};
        for (int i = 0; i < 2; i++) {
            if (sActors[i] == 0)
                sActors[i] = actor;
            if (sActors[i] == actor) {
                int state = (orig ? 1 : 0) | (hasSafety3D ? 2 : 0) | (forced ? 4 : 0);
                if (sLast[i] != state) {
                    sLast[i] = state;
                    Logging.Log("[OCoop] PATCH-0002 isValid actor=%p port=%d orig=%d hasSafety=%d -> %d",
                                (void*)actor, port, (int)orig, (int)hasSafety3D, (int)forced);
                }
                break;
            }
        }
        return forced;
    }
};
#endif

#if PATCH_0003_ENABLED
/* Trampoline on PlayerRecoverySafetyPoint::startRecovery(f32 height) @ 0x460f0c.
 * self (x0) = PlayerRecoverySafetyPoint*, mActor at self+0x00. Before the native
 * recovery runs, point the safety point at the partner so the bubble returns the
 * fallen player to the OTHER player. Trampoline (not inline) so the float `height`
 * arg is preserved across the call. */
HOOK_DEFINE_TRAMPOLINE(Patch0003RecoverToPartner) {
    static void Callback(void* self, float height) {
        uintptr_t s = (uintptr_t)self;
        uintptr_t actor = IsPtr8(s) ? *(uintptr_t*)s : 0;
        if (IsPtr8(actor)) {
            auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
            auto getTrans = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetTrans);
            auto getGravity = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetGravity);
            auto setSafetyPoint = OcoopFn<void (*)(void*, const void*, const void*, const void*)>(
                PatchOffsets::RecoverySetSafetyPoint);

            void* partner = nullptr;
            for (int i = 0; i < 4; i++) {
                void* p = getPlayerActor((const void*)actor, i);
                if (IsPtr8((uintptr_t)p) && (uintptr_t)p != actor) {
                    partner = p;
                    break;
                }
            }

            if (IsPtr8((uintptr_t)partner)) {
                const float* pos = getTrans(partner);
                const float* grav = getGravity((const void*)actor);
                if (pos && grav) {
                    float up[3] = {-grav[0], -grav[1], -grav[2]};
                    /* v4: pop above the partner, never at feet level (gravity
                     * is a unit vector, so the offset is in game units). */
                    float dst[3] = {pos[0] + up[0] * PATCH_0003_POP_UP_OFFSET,
                                    pos[1] + up[1] * PATCH_0003_POP_UP_OFFSET,
                                    pos[2] + up[2] * PATCH_0003_POP_UP_OFFSET};
                    setSafetyPoint(self, dst, up, nullptr);
                    Logging.Log("[OCoop] PATCH-0003 recover->partner actor=%p partner=%p pos=(%.1f,%.1f,%.1f) up-off=%.0f",
                                (void*)actor, partner, pos[0], pos[1], pos[2],
                                PATCH_0003_POP_UP_OFFSET);
                }
            } else {
                Logging.Log("[OCoop] PATCH-0003 no partner for actor=%p (solo recovery)", (void*)actor);
            }
        }
        Orig(self, height);
    }
};

 
HOOK_DEFINE_TRAMPOLINE(Patch0003ReassertDestination) {
    static void Callback(void* state) {
        uintptr_t st = (uintptr_t)state;
        uintptr_t recovery = 0;
        bool tracking = false;
        static float sTrackPos[4][3];
        if (IsPtr8(st)) {
            uintptr_t actor = *(uintptr_t*)(st + 0x18);
            recovery = *(uintptr_t*)(st + 0x20);
            if (IsPtr8(actor) && IsPtr8(recovery)) {
                auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
                auto getTrans = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetTrans);
                auto getGravity = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetGravity);
                auto getSafetyPoint = OcoopFn<const float* (*)(void*)>(PatchOffsets::RecoveryGetSafetyPoint);
                auto setSafetyPoint = OcoopFn<void (*)(void*, const void*, const void*, const void*)>(
                    PatchOffsets::RecoverySetSafetyPoint);

                int selfIdx = -1;
                void* partner = nullptr;
                for (int i = 0; i < 4; i++) {
                    void* p = getPlayerActor((const void*)actor, i);
                    if (!IsPtr8((uintptr_t)p))
                        continue;
                    if ((uintptr_t)p == actor)
                        selfIdx = i;
                    else if (partner == nullptr)
                        partner = p;
                }
                if (IsPtr8((uintptr_t)partner) && selfIdx >= 0 && selfIdx < 4) {
                    const float* pre = getSafetyPoint((void*)recovery);
                    const float* pos = getTrans(partner);
                    const float* grav = getGravity((const void*)actor);
                    if (pre && pos && grav) {
                        /* pre points INTO the recovery struct — copy BEFORE the
                         * overwrite or the log prints the new value (aliasing
                         * bug caught in the 2026-07-10 06-50 log). */
                        float preCopy[3] = {pre[0], pre[1], pre[2]};
                        float up[3] = {-grav[0], -grav[1], -grav[2]};
                        /* v4: same above-the-partner offset as startRecovery —
                         * the final hard-place must never be at feet level. */
                        float dst[3] = {pos[0] + up[0] * PATCH_0003_POP_UP_OFFSET,
                                        pos[1] + up[1] * PATCH_0003_POP_UP_OFFSET,
                                        pos[2] + up[2] * PATCH_0003_POP_UP_OFFSET};
                        /* Keeps mSafety3D (pos + gravity) fresh for the final
                         * landing; clears +0xb0, which we re-point below. */
                        setSafetyPoint((void*)recovery, dst, up, nullptr);
                        sTrackPos[selfIdx][0] = dst[0];
                        sTrackPos[selfIdx][1] = dst[1];
                        sTrackPos[selfIdx][2] = dst[2];
                        *(float**)(recovery + 0xb0) = sTrackPos[selfIdx];
                        tracking = true;
                        static unsigned n = 0;
                        n++;
                        if (n <= 6 || (n % 300) == 0) {
                            Logging.Log("[OCoop] PATCH-0003b exeRecovery #%u pre=(%.1f,%.1f,%.1f) -> partner=(%.1f,%.1f,%.1f) track=1",
                                        n, preCopy[0], preCopy[1], preCopy[2], pos[0], pos[1], pos[2]);
                        }
                    }
                }
            }
        }
        Orig(state);
        /* Drop the pointer to our buffer once the frame's native reads are
         * done — the next frame re-establishes it; nothing dangles after the
         * recovery episode ends. */
        if (tracking && IsPtr8(recovery))
            *(uintptr_t*)(recovery + 0xb0) = 0;
    }
};
#endif

#if PATCH_0016_ENABLED
 
HOOK_DEFINE_TRAMPOLINE(Patch0016ForceLandIn2D) {
    static void Callback(void* state) {
        Orig(state);
        uintptr_t st = (uintptr_t)state;
        if (!IsPtr8(st))
            return;
        uintptr_t actor = *(uintptr_t*)(st + 0x18);
        if (!IsPtr8(actor))
            return;
        auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(
            PatchOffsets::AlGetPlayerActor);
        int selfIdx = -1;
        uintptr_t partner = 0;
        for (int i = 0; i < 4; i++) {
            void* p = getPlayerActor((const void*)actor, i);
            if (!IsPtr8((uintptr_t)p))
                continue;
            if ((uintptr_t)p == actor)
                selfIdx = i;
            else if (partner == 0)
                partner = (uintptr_t)p;
        }
        if (!IsPtr8(partner) || selfIdx < 0)
            return;
        uintptr_t dimSelf = *(uintptr_t*)(actor + 0x150);
        uintptr_t dimPart = *(uintptr_t*)(partner + 0x150);
        if (!IsPtr8(dimSelf) || !IsPtr8(dimPart))
            return;
        const bool partner2D = (*(unsigned char*)(dimPart + 0x08) & 1) != 0 &&
                               (*(unsigned char*)(dimPart + 0x09) & 1) != 0;
        const bool self2D = (*(unsigned char*)(dimSelf + 0x08) & 1) != 0 &&
                            (*(unsigned char*)(dimSelf + 0x09) & 1) != 0;
        if (partner2D == self2D)
            return;
        /* to-2D waits the proven 120 fall frames for a possible native
         * landing; to-3D cannot land natively and the death-plane restart
         * cycle resets the fall after ~90 frames, so fire early. */
        const int timeoutFrames = partner2D ? PATCH_0016_FALL_TIMEOUT_FRAMES
                                            : PATCH_0016_FALL_TIMEOUT_TO3D_FRAMES;
        auto isGreaterEqualStep = OcoopFn<bool (*)(const void*, int)>(
            PatchOffsets::AlIsGreaterEqualStep);
        if (!isGreaterEqualStep(state, timeoutFrames))
            return;
        auto getTrans = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetTrans);
        auto setTrans = OcoopFn<void (*)(void*, const float*)>(PatchOffsets::AlSetTrans);
        const float* pp = getTrans((const void*)partner);
        if (pp == nullptr)
            return;
        float dst[3] = {pp[0], pp[1], pp[2]};
        setTrans((void*)actor, dst);
        if (partner2D) {
            /* to-2D: hand the native trio a valid keeper; keeper update then
             * sets mIs2D (in2D is already true at the partner), the model
             * changer swaps, and driver 0x420b58 snaps pose to the plane. */
            auto validate = OcoopFn<void (*)(void*)>(PatchOffsets::DimensionKeeperValidate);
            validate((void*)dimSelf);
        }
        uintptr_t vtable = *(uintptr_t*)st;
        if (!IsPtr8(vtable))
            return;
        /* The exact call exeFall's on-ground branch makes to end the state. */
        auto finish = *(void (**)(void*))(vtable + 0x28);
        static unsigned sFired = 0;
        if (sFired < 20) {
            sFired++;
            Logging.Log("[OCoop] PATCH-0016 v3 force-land idx=%d dir=%s after %d fall frames pos=(%.1f,%.1f,%.1f)",
                        selfIdx, partner2D ? "to2D" : "to3D",
                        timeoutFrames, dst[0], dst[1], dst[2]);
        }
        finish(state);
    }
};
#endif

#if PATCH_0017_ENABLED
/* 2D valve (Dokan) enter/exit for P2 — see the kill-switch comment for the
 * full mechanism. sQueryIdx is set ONLY for the dynamic extent of a
 * Dokan::receiveMsg whose `other` sensor host is a non-index-0 player; the
 * getPlayerActor trampoline below rewrites index 0 to it inside that scope and
 * is bit-identical to native everywhere else (sQueryIdx < 0, or an explicit
 * non-zero index, e.g. our own holder scans). receiveMsg runs on the game
 * update thread; the save/restore keeps nesting safe. v2 replaces the six
 * mov-w1 inline hooks, which exlaunch's execute-original-after-callback order
 * made no-ops (see PatchOffsets comment). */
namespace patch0017 {
static int sQueryIdx = -1;
}

HOOK_DEFINE_TRAMPOLINE(Patch0017GetPlayerActorRedirect) {
    static void* Callback(const void* actor, int idx) {
        if (idx == 0 && patch0017::sQueryIdx > 0)
            idx = patch0017::sQueryIdx;
        return Orig(actor, idx);
    }
};

HOOK_DEFINE_TRAMPOLINE(Patch0017DokanReceiveMsg) {
    static unsigned long Callback(void* self, void* msg, void* other, void* target) {
        int idx = -1;
        if (IsPtr8((uintptr_t)self) && IsPtr8((uintptr_t)other)) {
            auto isSensorPlayer =
                OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsSensorPlayer);
            if (isSensorPlayer(other)) {
                auto getSensorHost =
                    OcoopFn<void* (*)(const void*)>(PatchOffsets::AlGetSensorHost);
                uintptr_t host = (uintptr_t)getSensorHost(other);
                if (IsPtr8(host)) {
                    /* Holder scan, PATCH-0012 HolderIdxOf shape: index 0 keeps
                     * native behavior, so only 1..3 matter. */
                    auto getPlayerActor =
                        OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
                    for (int i = 1; i < 4; i++) {
                        if ((uintptr_t)getPlayerActor(self, i) == host) {
                            idx = i;
                            break;
                        }
                    }
                }
            }
        }
        int prev = patch0017::sQueryIdx;
        patch0017::sQueryIdx = idx;
        unsigned long ret = Orig(self, msg, other, target);
        patch0017::sQueryIdx = prev;
        if (idx > 0) {
            /* Discriminator log v2 (2026-07-15): classify the msg so a rejected
             * run separates "BindStart never arrives for P2" (sender-side gate)
             * from "BindStart arrives, judge rejects" (index-0 leftover). Bind
             * traffic is rare — log it unthrottled; FloorTouch and the generic
             * remainder keep the sparse throttle. */
            const char* kind = nullptr;
            if (IsPtr8((uintptr_t)msg)) {
                auto isBindStart =
                    OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsMsgBindStart);
                auto isBindInit =
                    OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsMsgBindInit);
                if (isBindStart(msg)) kind = "BINDSTART";
                else if (isBindInit(msg)) kind = "BINDINIT";
            }
            if (kind) {
                Logging.Log("[OCoop] PATCH-0017 dokan %s idx=%d ret=%d",
                            kind, idx, (int)(ret & 1));
            } else {
                bool floorTouch = false;
                if (IsPtr8((uintptr_t)msg)) {
                    auto isFloorTouch =
                        OcoopFn<bool (*)(const void*)>(PatchOffsets::AlIsMsgPlayerFloorTouch);
                    floorTouch = isFloorTouch(msg);
                }
                static unsigned nFloor = 0, n = 0;
                unsigned& c = floorTouch ? nFloor : n;
                c++;
                if (c <= 8 || (c % 240) == 0)
                    Logging.Log("[OCoop] PATCH-0017 dokan %s idx=%d ret=%d n=%u",
                                floorTouch ? "FLOORTOUCH" : "msg", idx,
                                (int)(ret & 1), c);
            }
        }
        return ret;
    }
};
#endif

#if PATCH_0004_ENABLED
/* Trampoline on al::ActorCameraTarget::calcTrans(sead::Vector3f* out) const
 * @ 0x971fd8. self (x0) = ActorCameraTarget*, out (x1) = Vector3f* the caller
 * fills with the tracked actor's world position. Both are pointers — no float
 * regs at this boundary. After Orig, out holds the tracked player's pos; we
 * nudge its x/z to the midpoint with the partner so the follow camera centers
 * between the two players (and every downstream consumer sees the midpoint). */
HOOK_DEFINE_TRAMPOLINE(Patch0004CoopCameraMidpoint) {
    static void Callback(void* self, float* out) {
        Orig(self, out);

        uintptr_t s = (uintptr_t)self;
        if (!IsPtr8(s) || out == nullptr)
            return;
        uintptr_t tracked = *(uintptr_t*)(s + 0x10);  // mActor
        if (!IsPtr8(tracked))
            return;

        auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
        auto getTrans = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetTrans);

        /* Confirm the tracked actor is a scene player and find the partner. If
         * getPlayerActor(tracked, i) ever returns `tracked`, it's in the holder
         * (a real player); the first other player is the partner. This gate
         * leaves non-player special cameras untouched. */
        bool trackedIsPlayer = false;
        void* partner = nullptr;
        for (int i = 0; i < 4; i++) {
            void* p = getPlayerActor((const void*)tracked, i);
            if (!IsPtr8((uintptr_t)p))
                continue;
            if ((uintptr_t)p == tracked)
                trackedIsPlayer = true;
            else if (partner == nullptr)
                partner = p;
        }
        if (!trackedIsPlayer || !IsPtr8((uintptr_t)partner))
            return;

        const float* tp = getTrans((const void*)tracked);
        const float* pp = getTrans((const void*)partner);
        if (tp == nullptr || pp == nullptr)
            return;

        float dx = (pp[0] - tp[0]) * 0.5f;
        float dz = (pp[2] - tp[2]) * 0.5f;
        out[0] += dx;   // x toward midpoint
        out[2] += dz;   // z toward midpoint (y left as Orig set it)

#if PATCH_0008_ENABLED
        /* Feed only scalar, current-frame separation to the final-pose hook.
         * No actor pointer survives this callback. */
        patch0008::ObserveHorizontalSeparation(pp[0] - tp[0], pp[2] - tp[2]);
#endif

        static unsigned calls = 0;
        static unsigned logged = 0;
        if ((calls++ % 120) == 0 && logged < 40) {
            logged++;
            Logging.Log("[OCoop] PATCH-0004 midpoint tracked=%p partner=%p tp=(%.0f,%.0f) pp=(%.0f,%.0f) d=(%.0f,%.0f)",
                        (void*)tracked, partner, tp[0], tp[2], pp[0], pp[2], dx, dz);
        }
    }
};
#endif

#if PATCH_0025_ENABLED
/* Shared-camera stick merge - see the kill-switch comment. Call-boundary
 * trampoline, so float use is safe. vtable+0x1a8 = PlayerActorBase::
 * getPlayerInfo (decomp virtual order; the native body reads the same slot);
 * PlayerInfo+0x80 = mInput (17th pointer, OdysseyDecomp PlayerInfo.h,
 * sizeof 0x150). Logging: 4 liveness samples + 16 override samples per boot,
 * zero steady-state log traffic. */
HOOK_DEFINE_TRAMPOLINE(Patch0025CameraStickP2) {
    static void Callback(float* out, const void* anchor) {
        Orig(out, anchor);
        if (out == nullptr || !IsPtr8((uintptr_t)anchor))
            return;
        auto tryGetPlayerActor =
            OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlTryGetPlayerActor);
        uintptr_t p2 = (uintptr_t)tryGetPlayerActor(anchor, 1);
        if (!IsPtr8(p2))
            return;  /* solo play or P2 not registered: native behavior */
        uintptr_t vt = *(uintptr_t*)p2;
        if (!IsPtr8(vt))
            return;
        auto getPlayerInfo = *(void* (**)(uintptr_t))(vt + 0x1a8);
        uintptr_t info = (uintptr_t)getPlayerInfo(p2);
        if (!IsPtr8(info))
            return;
        uintptr_t input = *(uintptr_t*)(info + 0x80);  /* PlayerInfo::mInput */
        if (!IsPtr8(input))
            return;
        auto getStickCameraRaw =
            OcoopFn<const float* (*)(uintptr_t)>(PatchOffsets::PlayerInputGetStickCameraRaw);
        const float* s2 = getStickCameraRaw(input);
        if (s2 == nullptr)
            return;
        float m1 = out[0] * out[0] + out[1] * out[1];
        float m2 = s2[0] * s2[0] + s2[1] * s2[1];
        static unsigned sLive = 0, sP2 = 0;
        if (sLive < 4) {
            sLive++;
            Logging.Log("[OCoop] PATCH-0025 camera stick consumer live p1=(%.2f,%.2f) p2=(%.2f,%.2f)",
                        out[0], out[1], s2[0], s2[1]);
        }
        constexpr float kDeadzoneSq = 0.01f;  /* |stick| > 0.1 */
        if (m2 > kDeadzoneSq && m2 > m1) {
            out[0] = s2[0];
            out[1] = s2[1];
            if (sP2 < 16) {
                sP2++;
                Logging.Log("[OCoop] PATCH-0025 camera stick src=p2 |p1|2=%.3f |p2|2=%.3f n=%u",
                            m1, m2, sP2);
            }
        }
    }
};
#endif

#if PATCH_0007_ENABLED
/* Trampoline on CameraPoserFollowLimit::calcDistanceRaw() const @ 0x0c8b9c.
 * Orig keeps Odyssey's native curve/request/collision behavior; this only
 * scales the final raw distance returned to the existing FollowLimit movement. */
HOOK_DEFINE_TRAMPOLINE(Patch0007CoopCameraZoom) {
    static float Callback(void* self) {
        float distance = Orig(self);
        return patch0007::ScaleRawDistance(distance, self);
    }
};
#endif

#if PATCH_0008_ENABLED
 
HOOK_DEFINE_TRAMPOLINE(Patch0008CoopCameraFinalZoom) {
    static void Callback(void* self, void* camera) {
        Orig(self, camera);

        uintptr_t out = (uintptr_t)camera;
        if (!IsPtr8(out))
            return;

        float* eye = (float*)(out + 0x38);
        const float* at = (const float*)(out + 0x44);
        patch0008::ScaleFinalPose(eye, at, self);
    }
};
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_036.inc"
#endif

#if PATCH_0006_ENABLED
/* Trampoline on PlayerActorHakoniwa::control() @ 0x420630 — runs once per
 * player per frame. All player fields used here are Ghidra-proven pointer
 * chains from the checkDeathArea decompilation (run 20260709-215354):
 * +0x148 HackCap*, +0x1f0 PlayerBindKeeper*, +0x1f8 PlayerCarryKeeper*,
 * +0x200 PlayerEquipmentUser*, +0x208 PlayerHackKeeper* (+0x70 = current
 * hack), +0x270 PlayerRecoverySafetyPoint*, +0x3b8 PlayerStateAbyss*. */
HOOK_DEFINE_TRAMPOLINE(Patch0006OutOfViewBubble) {
    static void Callback(void* self) {
        Orig(self);

        uintptr_t player = (uintptr_t)self;
        if (!IsPtr8(player))
            return;

#if PATCH_0010_ENABLED
        /* PATCH-0010 uses this existing live per-player control path as its
         * frame counter source. This runs before PATCH-0006's bubble selector
         * and changes none of that selector's behavior. */
        patch0009::TickTerminal(self);
#endif

#if PATCH_0014_ENABLED
        /* v8 demo-end HUD restore: level-triggered on "no demo active while
         * the scene-layout end hid our counter". No hook of its own. */
        p2hud::TickDemoRestore(self);
#endif
#if PATCH_0019_ENABLED && PATCH_0014_ENABLED
        coinrace::TickDemoRestore(self);
#endif

        auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
        auto getTrans = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetTrans);
        auto isDeadStatus = OcoopFn<bool (*)(const void*)>(PatchOffsets::PlayerFunctionIsPlayerDeadStatus);
        auto isNerve = OcoopFn<bool (*)(const void*, const void*)>(PatchOffsets::AlIsNerve);
        auto recoveryIsValid = OcoopFn<bool (*)(void*)>(PatchOffsets::RecoveryIsValid);
        const void* nrvAbyss =
            (const void*)exl::util::modules::GetTargetOffset(PatchOffsets::NrvPlayerActorHakoniwaAbyss);

#if PATCH_0014_ENABLED && PATCH_0014_CAPTURE_RESTORE_ENABLED
        /* Capture-scoped one-shot restore at the proven always-live entry,
         * before any holder/partner early return. Scan all holder slots because
         * the captured player's own callback is not a reliable anchor. */
        {
            static bool sPrevAnyHack = false;
            static unsigned sTicksSinceStart = 0;
            static bool sRestoreChecked = false;
            uintptr_t slotHack[4] = {0, 0, 0, 0};
            for (int hi = 0; hi < 4; hi++) {
                void* hp = getPlayerActor((const void*)player, hi);
                if (!IsPtr8((uintptr_t)hp))
                    continue;
                uintptr_t keeper = *(uintptr_t*)((uintptr_t)hp + 0x208);
                if (IsPtr8(keeper))
                    slotHack[hi] = *(uintptr_t*)(keeper + 0x70);
            }
            const bool anyHack = slotHack[0] != 0 || slotHack[1] != 0 ||
                                 slotHack[2] != 0 || slotHack[3] != 0;
            if (anyHack && !sPrevAnyHack) {
                sTicksSinceStart = 0;
                sRestoreChecked = false;
            } else if (anyHack && sTicksSinceStart < 240) {
                sTicksSinceStart++;
            } else if (!anyHack) {
                sTicksSinceStart = 0;
                sRestoreChecked = false;
            }
            if (anyHack && !sRestoreChecked && sTicksSinceStart >= 240) {
                sRestoreChecked = true;
                p2hud::RestoreAfterCapture(sTicksSinceStart);
            }
            sPrevAnyHack = anyHack;
        }
#endif

        /* Locate self in the holder + find the partner (live, never cached). */
        int selfIdx = -1;
        int partnerIdx = -1;
        void* partner = nullptr;
        for (int i = 0; i < 4; i++) {
            void* p = getPlayerActor((const void*)player, i);
            if (!IsPtr8((uintptr_t)p))
                continue;
            if ((uintptr_t)p == player)
                selfIdx = i;
            else if (partner == nullptr) {
                partner = p;
                partnerIdx = i;
            }
        }

        static unsigned sHold[4] = {0, 0, 0, 0};
        static unsigned sCooldown[4] = {0, 0, 0, 0};
        /* v2 movement tracking: position VALUES (not pointers) cached per
         * holder index; EMA of per-frame speed, ~1.2 s half-life. */
        static float sPrev[4][3];
        static bool sPrevValid[4] = {false, false, false, false};
        static float sSpeedEma[4] = {0, 0, 0, 0};
        if (selfIdx < 0 || selfIdx >= 4 || partnerIdx < 0 || partnerIdx >= 4 ||
            !IsPtr8((uintptr_t)partner))
            return;

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_037.inc"
#endif

        const auto& settings = ocoop::config::Get();
        const unsigned holdFrames = ocoop::config::BubbleHoldFrames();
        const unsigned cooldownFrames = ocoop::config::BubbleCooldownFrames();
        if (sCooldown[selfIdx] > 0)
            sCooldown[selfIdx]--;

        uintptr_t hackKeeper = *(uintptr_t*)(player + 0x208);
        uintptr_t partnerHackKeeper = *(uintptr_t*)((uintptr_t)partner + 0x208);
        uintptr_t selfHack = IsPtr8(hackKeeper) ? *(uintptr_t*)(hackKeeper + 0x70) : 0;
        uintptr_t partnerHack = IsPtr8(partnerHackKeeper) ?
                                *(uintptr_t*)(partnerHackKeeper + 0x70) : 0;
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_038.inc"
#endif

        /* Guards mirroring the native checkDeathArea preconditions: neither
         * player dead or already in the Abyss state. */
        if (isDeadStatus((const void*)player) || isDeadStatus(partner) ||
            isNerve((const void*)player, nrvAbyss) || isNerve(partner, nrvAbyss)) {
            sHold[selfIdx] = 0;
            return;
        }
         
        (void)partnerHack;

        const float* sp = getTrans((const void*)player);
        const float* pp = getTrans(partner);
        if (sp == nullptr || pp == nullptr)
            return;

        /* Update own speed EMA every frame (units/frame; running ~10-25).
         * Skip teleport artifacts (bubble placement, scene warp). */
        if (sPrevValid[selfIdx]) {
            float mx = sp[0] - sPrev[selfIdx][0];
            float my = sp[1] - sPrev[selfIdx][1];
            float mz = sp[2] - sPrev[selfIdx][2];
            float step = __builtin_sqrtf(mx * mx + my * my + mz * mz);
            if (step < 500.0f)
                sSpeedEma[selfIdx] += (step - sSpeedEma[selfIdx]) * 0.01f;
        }
        sPrev[selfIdx][0] = sp[0];
        sPrev[selfIdx][1] = sp[1];
        sPrev[selfIdx][2] = sp[2];
        sPrevValid[selfIdx] = true;

        float dx = sp[0] - pp[0], dy = sp[1] - pp[1], dz = sp[2] - pp[2];
        float dist2 = dx * dx + dy * dy + dz * dz;
        bool apart = dist2 > settings.bubbleDistance * settings.bubbleDistance;

        /* Throttled status line (only from the non-primary player's hook so
         * the pair is logged once): distance + both players' speed EMAs (the
         * v2 idle-selector inputs). */
        if (selfIdx != 0) {
            static unsigned calls = 0;
            static unsigned logged = 0;
            if (apart && (calls++ % 120) == 0 && logged < 60) {
                logged++;
                Logging.Log("[OCoop] PATCH-0006 status dist=%.0f hold=%u cooldown=%u emaSelf=%.1f emaPartner=%.1f",
                            __builtin_sqrtf(dist2), sHold[selfIdx], sCooldown[selfIdx],
                            sSpeedEma[selfIdx], sSpeedEma[partnerIdx]);
            }
        }

        if (!apart) {
            sHold[selfIdx] = 0;
            return;
        }
        /* v2 symmetric selector: the clearly-IDLE player bubbles (speed EMA
         * less than half the partner's). Ambiguous -> P2 fires (v1 fallback).
         * The two branches are mutually exclusive, so exactly one player can
         * fire per episode. */
        bool selfClearlyIdle = sSpeedEma[selfIdx] * 2.0f < sSpeedEma[partnerIdx];
        bool partnerClearlyIdle = sSpeedEma[partnerIdx] * 2.0f < sSpeedEma[selfIdx];
        bool iAmTheBubbler = (selfIdx == 0) ? selfClearlyIdle : !partnerClearlyIdle;
        if (!iAmTheBubbler || sCooldown[selfIdx] > 0)
            return;
        if (++sHold[selfIdx] < holdFrames)
            return;
        sHold[selfIdx] = 0;

         
        if (selfHack != 0) {
            auto cancelHackArea =
                OcoopFn<bool (*)(void*)>(PatchOffsets::PlayerHackKeeperCancelHackArea);
            bool ok = IsPtr8(hackKeeper) ? cancelHackArea((void*)hackKeeper) : false;
            Logging.Log("[OCoop] PATCH-0006 v3 unhack-for-bubble idx=%d dist=%.0f ok=%d",
                        selfIdx, __builtin_sqrtf(dist2), ok ? 1 : 0);
            sCooldown[selfIdx] = ok ? 120 : cooldownFrames;
            return;
        }

        /* Recovery must be valid (PATCH-0002-forced enable + hasSafety), or
         * the Abyss state's appear() would take the Fall path and KILL the
         * player instead of bubbling. */
        uintptr_t recovery = *(uintptr_t*)(player + 0x270);
        if (!IsPtr8(recovery) || !recoveryIsValid((void*)recovery)) {
            Logging.Log("[OCoop] PATCH-0006 skip: recovery not valid (recovery=%p)", (void*)recovery);
            sCooldown[selfIdx] = cooldownFrames;
            return;
        }

        uintptr_t hackCap = *(uintptr_t*)(player + 0x148);
        uintptr_t bindKeeper = *(uintptr_t*)(player + 0x1f0);
        uintptr_t carryKeeper = *(uintptr_t*)(player + 0x1f8);
        uintptr_t equipUser = *(uintptr_t*)(player + 0x200);
        uintptr_t stateAbyss = *(uintptr_t*)(player + 0x3b8);
        if (!IsPtr8(hackCap) || !IsPtr8(bindKeeper) || !IsPtr8(carryKeeper) ||
            !IsPtr8(equipUser) || !IsPtr8(stateAbyss)) {
            Logging.Log("[OCoop] PATCH-0006 skip: bad player fields cap=%p bind=%p carry=%p equip=%p abyss=%p",
                        (void*)hackCap, (void*)bindKeeper, (void*)carryKeeper,
                        (void*)equipUser, (void*)stateAbyss);
            sCooldown[selfIdx] = cooldownFrames;
            return;
        }

        auto forceRecovery = OcoopFn<void (*)(void*, void*, void*, void*, void*, void*)>(
            PatchOffsets::PlayerForceRecoveryHelper);
        Logging.Log("[OCoop] PATCH-0006 FIRE idx=%d dist=%.0f emaSelf=%.1f emaPartner=%.1f player=%p partner=%p",
                    selfIdx, __builtin_sqrtf(dist2), sSpeedEma[selfIdx], sSpeedEma[partnerIdx],
                    (void*)player, partner);
        forceRecovery((void*)player, (void*)hackCap, (void*)carryKeeper,
                      (void*)bindKeeper, (void*)equipUser, (void*)stateAbyss);
        sCooldown[selfIdx] = cooldownFrames;
    }
};
#endif

#if PATCH_0009_ENABLED
/* P2-only gates. P1 always reaches Orig and retains exact vanilla health,
 * invulnerability, HUD, and global game-over behavior. */
HOOK_DEFINE_TRAMPOLINE(Patch0009P2Damage) {
    static void Callback(void* self, int damageInvalid) {
        if (patch0009::HandleDamage(self, damageInvalid, false
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_039.inc"
#endif
        ))
            return;
        Orig(self, damageInvalid);
    }
};

HOOK_DEFINE_TRAMPOLINE(Patch0009P2DamageForce) {
    static void Callback(void* self, int damageInvalid) {
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_040.inc"
#endif
        if (patch0009::HandleDamage(self, damageInvalid, true
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_041.inc"
#endif
        ))
            return;
        Orig(self, damageInvalid);
    }
};

HOOK_DEFINE_TRAMPOLINE(Patch0009P2Dead) {
    static void Callback(void* self) {
        uintptr_t keeper = (uintptr_t)self;
        void* actor = IsPtr8(keeper) ? *(void**)keeper : nullptr;
        if (!patch0009::IsP2(actor)) {
            Orig(self);
            return;
        }

        /* Fail-safe for P2 paths that call dead() directly (press/sink/etc.).
         * Never let them poison P1's shared GameData life counter. */
#if PATCH_0010_ENABLED
#if PATCH_0018_ENABLED
        patch0009::BeginP2TerminalFromDead(actor, "keeper-dead");
#else
        patch0009::BeginP2Terminal(actor, "keeper-dead");
#endif
#else
        patch0009::StartPlayerRecovery(actor, "dead", false);
#endif
    }
};
#endif

#if PATCH_0010_ENABLED
/* Static evidence (Ghidra 20260710-234848): the stock helper resolves player
 * index 0 even when its actor argument is P2. Override only the P2 terminal
 * episode so PlayerStateDamageLife can select its own native Dead nerve; every
 * non-P2 call retains the exact stock result. */
HOOK_DEFINE_TRAMPOLINE(Patch0010P2DeadStatus) {
    static bool Callback(const void* actor) {
        if (patch0009::IsP2((void*)actor))
            return patch0009::sP2Terminal;
        bool stock = Orig(actor);
        if (stock && patch0009::IsP1((void*)actor))
            patch0009::BeginP1Terminal((void*)actor, "native-dead-status");
        return stock;
    }
};

/* Ghidra 20260710-235537: state+0x18 is its actor and state+0x38 is the
 * PlayerAnimator. The game itself ends this state when isAnimEnd() becomes
 * true, so sample that exact predicate before calling Orig. */
HOOK_DEFINE_TRAMPOLINE(Patch0010P2DamageLifeDead) {
    static void Callback(void* state) {
        uintptr_t self = (uintptr_t)state;
        uintptr_t actor = IsPtr8(self) ? *(uintptr_t*)(self + 0x18) : 0;
        uintptr_t animator = IsPtr8(self) ? *(uintptr_t*)(self + 0x38) : 0;
        bool animationEnded = false;
        bool tracked = IsPtr8(actor) &&
            ((patch0009::sP1Terminal && patch0009::IsP1((void*)actor)) ||
             (patch0009::sP2Terminal && patch0009::IsP2((void*)actor)));
        if (tracked && IsPtr8(animator)) {
            auto isAnimEnd = OcoopFn<bool (*)(const void*)>(PatchOffsets::PlayerAnimatorIsAnimEnd);
            animationEnded = isAnimEnd((const void*)animator);
        }
        patch0009::NoteDeadState(state, animationEnded);
        Orig(state);
    }
};
#endif

#if PATCH_0015_ENABLED
/* StageSceneStateMiss::checkMiss is the sole selector that enters the global
 * miss state. Native code checks only holder index 0. Preserve vanilla behavior
 * when no P2 is registered; in co-op allow the miss only while P1's native dead
 * status overlaps P2's private terminal episode. HOOK_DEFINE_REPLACE does not
 * allocate an original-instruction trampoline, keeping inventory at 19/20. */
HOOK_DEFINE_REPLACE(Patch0015TeamMissGate) {
    static bool Callback(const void* self) {
        uintptr_t state = (uintptr_t)self;
        if (!IsPtr8(state))
            return false;
        uintptr_t scene = *(uintptr_t*)(state + 0x18);
        if (!IsPtr8(scene))
            return false;

        auto getHolder = OcoopFn<void* (*)(const void*)>(PatchOffsets::AlGetScenePlayerHolder);
        auto getPlayer = OcoopFn<void* (*)(const void*, int)>(
            PatchOffsets::AlGetPlayerActorFromHolder);
        auto isDeadStatus = OcoopFn<bool (*)(const void*)>(
            PatchOffsets::PlayerFunctionIsPlayerDeadStatus);
        void* holder = getHolder((const void*)scene);
        if (!IsPtr8((uintptr_t)holder))
            return false;
        void* p1 = getPlayer(holder, 0);
        if (!IsPtr8((uintptr_t)p1))
            return false;

        bool p1Dead = isDeadStatus(p1);
        /* PlayerHolder +0x0c is the proven registered player count. Preserve
         * vanilla single-player behavior without an out-of-range index read. */
        int playerNum = *(int*)((uintptr_t)holder + 0x0c);
        if (playerNum < 2)
            return p1Dead;
        void* p2 = getPlayer(holder, 1);
        if (!IsPtr8((uintptr_t)p2))
            return p1Dead;
        bool teamDead = p1Dead && patch0009::sP2Terminal;

        static int lastGate = -1;
        int gate = !p1Dead ? 0 : (teamDead ? 2 : 1);
        if (gate != lastGate) {
            lastGate = gate;
            if (gate == 1) {
                Logging.Log("[OCoop] PATCH-0015 full miss suppressed p1Down=1 p2Down=0 delaySeconds=%.2f",
                            ocoop::config::Get().respawnDelaySeconds);
            } else if (gate == 2) {
                Logging.Log("[OCoop] PATCH-0015 full miss allowed p1Down=1 p2Down=1");
            }
        }
        return teamDead;
    }
};
#endif

#if PATCH_0009_ENABLED
HOOK_DEFINE_TRAMPOLINE(Patch0009LifeMaxUpAcquire) {
    static void Callback(const void* actor) {
        Orig(actor);
        const char* collector = patch0009::IsP2((void*)actor) ? "P2" :
                                (patch0009::IsP1((void*)actor) ? "P1" : "other");
        patch0009::GrantP2LifeUp();
        Logging.Log("[OCoop] PATCH-0009 Life-Up broadcast collector=%s actor=%p p2hp=%d p2max=%d",
                    collector, actor, patch0009::sP2Health,
                    patch0009::sP2MaxHealth);
    }
};
#endif

#if PATCH_0009_MOON_HEAL_ENABLED && PATCH_0009_ENABLED
/* Non-demo moon path: Shine::exeGot calls this actor wrapper on first step
 * only when rs::isActiveDemo(shine) is false (runtime-confirmed lr 0x1d2de0). */
HOOK_DEFINE_TRAMPOLINE(Patch0009MoonHealActorMax) {
    static void Callback(const void* actor) {
        Orig(actor);
        patch0009::HealP2Full("actor-max", true);
    }
};

 
HOOK_DEFINE_TRAMPOLINE(Patch0009MoonHealSystemMax) {
    static void Callback(const void* holder) {
        const uintptr_t lr = (uintptr_t)__builtin_return_address(0);
        Orig(holder);
        const uintptr_t base = (uintptr_t)exl::util::modules::GetTargetOffset(0);
        const uintptr_t lrNso = (lr >= base) ? lr - base : 0;
        const bool mainModule = lrNso > 0 && lrNso < 0xbef048UL;
        const bool sceneAlive = !mainModule || lrNso == 0x4dc6b4;
        if (!sceneAlive) {
            Logging.Log("[OCoop] PATCH-0009 moon-heal system-max sequence-level lr_nso=0x%lx hud-skip",
                        (unsigned long)lrNso);
        }
        patch0009::HealP2Full("system-max", sceneAlive);
    }
};
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_042.inc"
#endif

#if PATCH_0011_ENABLED
/* Trampoline on rs::tryChangeNextStage(GameDataHolder*, al::Scene*): after the
 * native P1-only poll, run the identical check for player index 1. Field
 * provenance: holder+0x49 = change-requested flag (GameDataHolder::
 * changeNextStage decompile, run 20260711-193754); actor+0x20 =
 * IUseSceneObjHolder sub-object handed to GameDataHolderAccessor::C2 (the
 * native P1 branch does exactly this, run 20260711-201724). */
HOOK_DEFINE_TRAMPOLINE(Patch0011P2AreaChangeStage) {
    static unsigned long Callback(void* holder, void* scene) {
        unsigned long ret = Orig(holder, scene);
        uintptr_t h = (uintptr_t)holder;
        if (!IsPtr8(h) || !IsPtr8((uintptr_t)scene))
            return ret;
        if (*(char*)(h + 0x49) != 0)  /* change already requested this frame */
            return ret;
        auto getScenePlayerHolder = OcoopFn<void* (*)(const void*)>(PatchOffsets::AlGetScenePlayerHolder);
        auto getPlayerActorAt = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActorFromHolder);
        auto isInChangeStageArea = OcoopFn<bool (*)(const void*, const void*)>(PatchOffsets::RsIsInChangeStageArea);
        auto isDeadStatus = OcoopFn<bool (*)(const void*)>(PatchOffsets::PlayerFunctionIsPlayerDeadStatus);
        auto accessorCtor = OcoopFn<void (*)(void*, const void*)>(PatchOffsets::GameDataHolderAccessorCtor);
        auto findAreaAndChange = OcoopFn<void (*)(uintptr_t, const void*, const void*)>(
            PatchOffsets::GameDataFindAreaAndChangeNextStage);

        void* playerHolder = getScenePlayerHolder(scene);
        if (!IsPtr8((uintptr_t)playerHolder))
            return ret;
        void* p2 = getPlayerActorAt(playerHolder, 1);
        if (!IsPtr8((uintptr_t)p2) || isDeadStatus(p2))
            return ret;
        if (!isInChangeStageArea(p2, nullptr))
            return ret;
        uintptr_t accessor = 0;
        accessorCtor(&accessor, (void*)((uintptr_t)p2 + 0x20));
        if (!IsPtr8(accessor))
            return ret;
        findAreaAndChange(accessor, p2, nullptr);
        static unsigned n = 0;
        if (n < 8) {
            n++;
            Logging.Log("[OCoop] PATCH-0011 p2 area-enter -> stage change requested (p2=%p flag=%d)",
                        p2, (int)*(char*)(h + 0x49));
        }
        return ret;
    }
};
#endif

#if PATCH_0012_ENABLED
/* Capture-revert shield. Both hooks are trampolines at function entry (entry
 * instructions verified non-PC-relative, Ghidra run 20260711-234031). Player
 * fields: +0x208 PlayerHackKeeper* (same chain PATCH-0006 uses); keeper
 * +0x70 hack sensor (mid-hack test), +0x5a mIsHackDemoStarted (bool, decomp
 * PlayerHackKeeper.h). sShielded is OUR bookkeeping keyed by holder index
 * (values only, no cached pointers) and is re-assigned on every
 * startDemoPuppetable call, so a stale flag self-heals at the next demo. */
namespace patch0012 {
static bool sShielded[4] = {false, false, false, false};

static int HolderIdxOf(uintptr_t player) {
    auto getPlayerActor = OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
    for (int i = 0; i < 4; i++) {
        if ((uintptr_t)getPlayerActor((const void*)player, i) == player)
            return i;
    }
    return -1;
}
}  // namespace patch0012

HOOK_DEFINE_TRAMPOLINE(Patch0012DemoShieldStart) {
    static void Callback(void* self) {
        uintptr_t player = (uintptr_t)self;
        if (IsPtr8(player)) {
            int idx = patch0012::HolderIdxOf(player);
            if (idx >= 0) {
                bool shield = false;
                uintptr_t keeper = *(uintptr_t*)(player + 0x208);
                if (IsPtr8(keeper) && *(uintptr_t*)(keeper + 0x70) != 0 &&
                    *(unsigned char*)(keeper + 0x5a) == 0) {
                    /* Mid-hack bystander candidate: shield only if some OTHER
                     * player's keeper is in its hack-start demo right now. */
                    auto getPlayerActor =
                        OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
                    for (int i = 0; i < 4 && !shield; i++) {
                        uintptr_t other = (uintptr_t)getPlayerActor((const void*)player, i);
                        if (!IsPtr8(other) || other == player)
                            continue;
                        uintptr_t otherKeeper = *(uintptr_t*)(other + 0x208);
                        if (IsPtr8(otherKeeper) && *(unsigned char*)(otherKeeper + 0x5a) != 0)
                            shield = true;
                    }
                    if (shield) {
                        *(unsigned char*)(keeper + 0x5a) = 1;
                        static unsigned n = 0;
                        if (n < 40) {
                            n++;
                            Logging.Log("[OCoop] PATCH-0012 shield ON idx=%d (partner hack-start demo)", idx);
                        }
                    }
                }
                patch0012::sShielded[idx] = shield;
            }
        }
        Orig(self);
    }
};

HOOK_DEFINE_TRAMPOLINE(Patch0012DemoShieldEnd) {
    static void Callback(void* self) {
        /* Orig first: with +0x5a still 1 it early-returns and KEEPS the hack
         * state. Then drop our injected flag so exeHackDemoPuppetable's next
         * tick returns the player to the plain Hack nerve natively. */
        Orig(self);
        uintptr_t player = (uintptr_t)self;
        if (!IsPtr8(player))
            return;
        int idx = patch0012::HolderIdxOf(player);
        if (idx < 0 || !patch0012::sShielded[idx])
            return;
        patch0012::sShielded[idx] = false;
        uintptr_t keeper = *(uintptr_t*)(player + 0x208);
        if (IsPtr8(keeper))
            *(unsigned char*)(keeper + 0x5a) = 0;
        static unsigned n = 0;
        if (n < 40) {
            n++;
            Logging.Log("[OCoop] PATCH-0012 shield OFF idx=%d (demo end, hack kept)", idx);
        }
    }
};
#endif

#if PATCH_0013_ENABLED
/* Cap-return owner fix (v2). Trampoline at rs::getPlayerHeadPos entry
 * (verified non-PC-relative, run 20260712-104703). When the queried actor is
 * a HackCap owned by a player other than index 0 (owner scan:
 * al::getPlayerActor live each call, keeper = player+0x208, keeper+0x08 =
 * mHackCap per decomp PlayerHackKeeper.h), replay the native chain on the
 * OWNER, corrected per the instruction-level listing (run 20260712-151606):
 * vcall vtable+0x1a8 -> PlayerInfo*, receiver = *(info+0x78)
 * (mFormSensorCollisionArranger) -> getHeadPos(); native fallback =
 * getTrans(CAP) (mov x0,x19 @0x56f650). v1 crashed by calling getHeadPos on
 * the PlayerInfo itself. Every non-cap caller (28 others) and player-0 caps
 * fall through to Orig. */
HOOK_DEFINE_TRAMPOLINE(Patch0013CapReturnOwner) {
    static const float* Callback(const void* actor) {
        uintptr_t cap = (uintptr_t)actor;
        if (IsPtr8(cap)) {
            auto getPlayerActor =
                OcoopFn<void* (*)(const void*, int)>(PatchOffsets::AlGetPlayerActor);
            for (int i = 1; i < 4; i++) {  /* owner 0 == native behavior already */
                uintptr_t player = (uintptr_t)getPlayerActor(actor, i);
                if (!IsPtr8(player))
                    continue;
                uintptr_t keeper = *(uintptr_t*)(player + 0x208);
                if (!IsPtr8(keeper) || *(uintptr_t*)(keeper + 0x08) != cap)
                    continue;
                static unsigned n = 0;
                if (n < 20) {
                    n++;
                    Logging.Log("[OCoop] PATCH-0013 cap-return owner idx=%d cap=%p", i,
                                (void*)cap);
                }
                uintptr_t vt = *(uintptr_t*)player;
                if (IsPtr8(vt)) {
                    auto getPlayerInfo =
                        reinterpret_cast<void* (*)(const void*)>(*(uintptr_t*)(vt + 0x1a8));
                    uintptr_t info = (uintptr_t)getPlayerInfo((const void*)player);
                    if (IsPtr8(info)) {
                        uintptr_t arranger = *(uintptr_t*)(info + 0x78);
                        if (IsPtr8(arranger)) {
                            auto getHeadPos =
                                OcoopFn<const float* (*)(const void*)>(PatchOffsets::ArrangerGetHeadPos);
                            return getHeadPos((const void*)arranger);
                        }
                    }
                }
                /* Native fallback shape: getTrans on the queried CAP. */
                auto getTrans = OcoopFn<const float* (*)(const void*)>(PatchOffsets::AlGetTrans);
                return getTrans(actor);
            }
        }
        return Orig(actor);
    }
};
#endif

#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_043.inc"
#endif

extern "C" void exl_main(void* x0, void* x1) {
    exl::hook::Initialize();
    exl::patch::impl::InitPatcherImpl();
    ocoop::diagnostics::Initialize();
    Logging.Log("[OCoop] init (OCoopMod, target 0100000000010000 v1.0.0)");

#if PATCH_0001_ENABLED
    Patch0001CaptureInitInfo::InstallAtOffset(PatchOffsets::P1InitPlayerVCall);
    Patch0001SpawnP2::InstallAtOffset(PatchOffsets::P1PostRegisterInsn);
    Logging.Log("[OCoop] PATCH-0001 installed (A capture @ 0x4c9fa4, B spawn @ 0x4c9fd8)");
#endif
#if PATCH_0002_ENABLED
    Patch0002ForceRecovery::InstallAtOffset(PatchOffsets::RecoveryIsValid);
    Logging.Log("[OCoop] PATCH-0002 installed (force recovery via isValid @ 0x460c90)");
#endif
#if PATCH_0003_ENABLED
    Patch0003RecoverToPartner::InstallAtOffset(PatchOffsets::RecoveryStartRecovery);
    Patch0003ReassertDestination::InstallAtOffset(PatchOffsets::RecoveryDeadExeRecovery);
    Logging.Log("[OCoop] PATCH-0003 installed (recover-to-partner @ 0x460f0c + v2 re-assert @ 0x479884)");
#endif
#if PATCH_0016_ENABLED
    Patch0016ForceLandIn2D::InstallAtOffset(PatchOffsets::RecoveryDeadExeFall);
    Logging.Log("[OCoop] PATCH-0016 v3 installed (cross-dimension bubble force-land, to2D=%d / to3D=%d fall frames)",
                PATCH_0016_FALL_TIMEOUT_FRAMES, PATCH_0016_FALL_TIMEOUT_TO3D_FRAMES);
#endif
#if PATCH_0017_ENABLED
    Patch0017DokanReceiveMsg::InstallAtOffset(PatchOffsets::DokanReceiveMsg);
    Patch0017GetPlayerActorRedirect::InstallAtOffset(PatchOffsets::AlGetPlayerActor);
    Logging.Log("[OCoop] PATCH-0017 v2 installed (2D valve P2 enter/exit; dokan receiveMsg scope + getPlayerActor redirect)");
#endif
#if PATCH_0019_ENABLED && PATCH_0014_ENABLED
#if PATCH_0028_ENABLED
    Patch0028BlockBrick2DCoin::InstallAtOffset(PatchOffsets::BlockBrick2DReceiveMsg);
    Logging.Log("[OCoop] PATCH-0028 installed (BlockBrick2D P1/P2 attacker provenance + exact Coin2D sidecar credit; native total untouched)");
#endif
    Patch0019DirectCoin3D::InstallAtOffset(PatchOffsets::AlSendMsgPlayerItemGet);
    Patch0019DirectCoin2D::InstallAtOffset(PatchOffsets::Coin2DReceiveMsg);
    Patch0019CoinCountUpScope::InstallAtOffset(PatchOffsets::CoinExeCountUp);
    Patch0019ScopedAddCoin::InstallAtOffset(PatchOffsets::GameDataAddCoin);
    Logging.Log("[OCoop] PATCH-0019 combined COINS/MOONS HUD installed (coin target=%d moon target=%d native pools untouched)",
                ocoop::config::Get().coinRaceTarget,
                ocoop::config::Get().moonRaceTarget);
#if PATCH_0020_ENABLED
    Patch0020ShineCollector::InstallAtOffset(PatchOffsets::ShineReceiveMsg);
    Logging.Log("[OCoop] PATCH-0020 installed (per-player ShineGet crediting; native moon progression untouched)");
#if PATCH_0021_ENABLED
    Logging.Log("[OCoop] PATCH-0021 installed (persistent per-save/per-world coin+moon scores; v1 moon migration; two-slot journal)");
#if PATCH_0022_ENABLED
    Logging.Log("[OCoop] PATCH-0022 installed (native first-vs-repeat Shine selector; repeat five-coin ownership; coalesced persistence)");
#endif
#endif
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_044.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_045.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_046.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_047.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_048.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_059.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_061.inc"
#endif
#endif
#if PATCH_0004_ENABLED
    Patch0004CoopCameraMidpoint::InstallAtOffset(PatchOffsets::ActorCameraTargetCalcTrans);
    Logging.Log("[OCoop] PATCH-0004 installed (co-op camera midpoint @ 0x971fd8)");
#endif
#if PATCH_0005_ENABLED
    /* No hook of its own — rides in PATCH-0001 hook B (changeMultiPlayMode
     * after P2 registers). Logged here for build-identity checks. */
    Logging.Log("[OCoop] PATCH-0005 armed (multi-play pad mode on P2 spawn)");
#endif
#if PATCH_0006_ENABLED
    Patch0006OutOfViewBubble::InstallAtOffset(PatchOffsets::PlayerHakoniwaControl);
    Logging.Log("[OCoop] PATCH-0006 installed (out-of-view bubble via control @ 0x420630, dist=%.0f)",
                (double)ocoop::config::Get().bubbleDistance);
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_049.inc"
#endif
#endif
#if PATCH_0024_ENABLED
    Patch0024ChangeWorldDetach::InstallAtOffset(PatchOffsets::DemoChangeWorldSceneExeTalk);
    Logging.Log("[OCoop] PATCH-0024 installed (change-world HUD detach @ 0x4a7070)");
#endif
#if PATCH_0025_ENABLED
    Patch0025CameraStickP2::InstallAtOffset(PatchOffsets::PlayerCameraCalcCameraMoveInput);
    Logging.Log("[OCoop] PATCH-0025 installed (shared-camera stick merge @ 0x57309c; P2 via tryGetPlayerActor)");
#endif
#if PATCH_0026_ENABLED
    Logging.Log("[OCoop] PATCH-0026 armed (custom MoonTotal uses current-kingdom getGotShineNum @ 0x528974)");
#endif
#if PATCH_0027_ENABLED
    Logging.Log("[OCoop] PATCH-0027 armed (Grand Shine type 2 credits three private moons; repeat selector preserved)");
#endif
#if PATCH_0009_ENABLED
    Patch0009P2Damage::InstallAtOffset(PatchOffsets::PlayerDamageKeeperDamage);
    Patch0009P2DamageForce::InstallAtOffset(PatchOffsets::PlayerDamageKeeperDamageForce);
    Patch0009P2Dead::InstallAtOffset(PatchOffsets::PlayerDamageKeeperDead);
    Patch0009LifeMaxUpAcquire::InstallAtOffset(PatchOffsets::GameDataGetLifeMaxUpItem);
    Logging.Log("[OCoop] PATCH-0009 installed (P2 private health, event-driven Life-Up, base max=%d)",
                PATCH_0009_P2_HEALTH_MAX);
#endif
#if PATCH_0009_MOON_HEAL_ENABLED && PATCH_0009_ENABLED
    Patch0009MoonHealActorMax::InstallAtOffset(PatchOffsets::GameDataRecoveryPlayerMax);
    Patch0009MoonHealSystemMax::InstallAtOffset(
        PatchOffsets::GameDataRecoveryPlayerMaxForSystem);
    Logging.Log("[OCoop] PATCH-0009 moon-heal broadcast installed (actor+system full-recovery wrappers)");
#endif
#if PATCH_0010_ENABLED
    Patch0010P2DeadStatus::InstallAtOffset(PatchOffsets::PlayerFunctionIsPlayerDeadStatus);
    Patch0010P2DamageLifeDead::InstallAtOffset(PatchOffsets::PlayerStateDamageLifeExeDead);
    Logging.Log("[OCoop] PATCH-0010 installed (symmetric native death + delayed respawn seconds=%.2f frames=%u)",
                ocoop::config::Get().respawnDelaySeconds,
                ocoop::config::RespawnDelayFrames());
#endif
#if PATCH_0018_ENABLED && PATCH_0002_ENABLED && PATCH_0009_ENABLED && PATCH_0010_ENABLED
    Logging.Log("[OCoop] PATCH-0018 armed (P2 pre-movement last-heart terminal selector; zero new hooks)");
#endif
#if PATCH_0015_ENABLED
    Patch0015TeamMissGate::InstallAtOffset(PatchOffsets::StageSceneStateMissCheckMiss);
    Logging.Log("[OCoop] PATCH-0015 installed (full miss only when both players down; replace/no trampoline)");
#endif
#if PATCH_0014_ENABLED
    Patch0014P2HudLayoutCtor::InstallAtOffset(PatchOffsets::StageSceneLayoutCtor);
    Patch0014P2HudLayoutEnd::InstallAtOffset(PatchOffsets::StageSceneLayoutEnd);
    Patch0014P2HudLayoutStart::InstallAtOffset(PatchOffsets::StageSceneLayoutStart);
    Logging.Log("[OCoop] PATCH-0014 v8 installed (P2 CounterLife HUD; demo-aware scene-layout end + isActiveDemo restore)");
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_050.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_051.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_052.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_053.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_054.inc"
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_055.inc"
#endif
#if PATCH_0007_ENABLED
    Patch0007CoopCameraZoom::InstallAtOffset(PatchOffsets::CameraPoserFollowLimitCalcDistanceRaw);
    Logging.Log("[OCoop] PATCH-0007 installed (co-op FollowLimit zoom @ 0x0c8b9c, base=%.2f max=%.2f)",
                (double)PATCH_0007_BASE_ZOOM, (double)PATCH_0007_MAX_ZOOM);
#endif
#if PATCH_0008_ENABLED
    Patch0008CoopCameraFinalZoom::InstallAtOffset(PatchOffsets::CameraPoserFollowLimitCalcCameraPose);
    Logging.Log("[OCoop] PATCH-0008 installed (final-pose co-op zoom @ 0x0caa60; defaults base=%.2f max=%.2f start=%.0f full=%.0f lerp=%.3f; LayeredFS config reloads each stage)",
                patch0008::BaseZoom(), patch0008::MaxZoom(),
                patch0008::SeparationStart(), patch0008::SeparationFull(),
                patch0008::Lerp());
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_056.inc"
#endif
#if PATCH_0011_ENABLED
    Patch0011P2AreaChangeStage::InstallAtOffset(PatchOffsets::RsTryChangeNextStage);
    Logging.Log("[OCoop] PATCH-0011 installed (P2 ChangeStage-area poll @ 0x4d2c54)");
#endif
#if PATCH_0012_ENABLED
    Patch0012DemoShieldStart::InstallAtOffset(PatchOffsets::PlayerHakoniwaStartDemoPuppetable);
    Patch0012DemoShieldEnd::InstallAtOffset(PatchOffsets::PlayerHakoniwaEndDemoPuppetable);
    Logging.Log("[OCoop] PATCH-0012 installed (capture shield @ 0x421b84/0x421e2c)");
#endif
#if PATCH_0013_ENABLED
    Patch0013CapReturnOwner::InstallAtOffset(PatchOffsets::RsGetPlayerHeadPos);
    Logging.Log("[OCoop] PATCH-0013 v2 installed (cap-return owner @ 0x56f618)");
#endif
#if OCOOP_DEV_DIAGNOSTICS
#include "program/diagnostics_private/fragment_057.inc"
#endif
}

extern "C" NORETURN void exl_exception_entry() {
    EXL_ABORT("Default exception handler called!");
}
