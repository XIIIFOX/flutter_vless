import Foundation

// ACTUAL_RATE_HELPER
private enum FixturePrivacy {case `public`}
private struct FixtureLogMessage: ExpressibleByStringInterpolation {
    init(stringLiteral value: String){}
    init(stringInterpolation: StringInterpolation){}
    struct StringInterpolation: StringInterpolationProtocol {
        init(literalCapacity: Int,interpolationCount: Int){}
        mutating func appendLiteral(_ value: String){}
        mutating func appendInterpolation<T>(_ value:T){}
        mutating func appendInterpolation<T>(_ value:T,privacy:FixturePrivacy){}
    }
}
private struct Log {func info(_ text:FixtureLogMessage){};func error(_ text:FixtureLogMessage){}}
private let pluginLog=Log()
private func pluginDebug(_ text:String){}
private enum NativeLogPrivacy {static func operationError(_ error:Error)->NSError {error as NSError}}
private enum Status:Int {case invalid,disconnected,connecting,connected,reasserting,disconnecting}
private final class Session {}
private final class PacketTunnelManager {
    var manager:Session?=Session()
    var status:Status? = .connected
    var connectedDate:Date?=Date(timeIntervalSince1970:100)
    var forwardingReady=false
    var isRecoveryEnabled=false
    var replies:[CheckedContinuation<Data?,Error>?]=[]
    var trafficRequests=0
    func sendProviderMessage(data:Data)async throws->Data? {
        if data==Data("xray_traffic".utf8){trafficRequests+=1;return Data("100,200".utf8)}
        precondition(data==Data("xray_runtime_state".utf8))
        return try await withCheckedThrowingContinuation {replies.append($0)}
    }
    func finish(_ index:Int,_ text:String?=nil,failure:Bool=false){
        guard replies.indices.contains(index),let reply=replies[index]else{return}
        replies[index]=nil
        if failure {reply.resume(throwing:NSError(domain:"inert",code:1))}
        else {reply.resume(returning:text.map{Data($0.utf8)})}
    }
    func finishAll(){for index in replies.indices{finish(index)}}
// ACTUAL_MANAGER_REFRESH
}
private final class ProxyOnlyRunner {
    var isRunning=false;var connectedDate:Date?
    func queryTrafficStats()->(upload:Int,download:Int,uploadSpeed:Int,downloadSpeed:Int){(0,0,0,0)}
}
private final class Host {
    var packetTunnelManager:PacketTunnelManager?
    let proxyOnlyRunner=ProxyOnlyRunner()
    var timer:Timer?;var readinessTimer:Timer?
    var readinessPollingOwner:(manager:PacketTunnelManager,connectedDate:Date?,generation:UInt64)?
    var eventSink:(()->Void)?
    var totalUpload=0,totalDownload=0,uploadSpeed=0,downloadSpeed=0
    var trafficPollingGeneration:UInt64=0;var trafficPollInFlight=false
    var previousTrafficSampleTime:UInt64?;var previousTrafficUpload:Int?;var previousTrafficDownload:Int?
    var time:UInt64=1_000_000_000
    lazy var trafficClock:()->UInt64={[unowned self]in self.time}
    var lastTrafficLogDate=Date.distantPast,lastProviderDebugLogDate=Date.distantPast
    var lastNetworkSnapshotLogDate=Date.distantPast,lastAppNetworkProbeDate=Date.distantPast
    var didScheduleConnectedDiagnostics=false;var events:[String]=[]
    init(_ manager:PacketTunnelManager){packetTunnelManager=manager}
    func emitStatus(duration:Int,state:String,reason:String){events.append(state)}
    func logProviderDebugSnapshot(){};func logSystemNetworkSnapshot(reason:String){}
    func parkTimers(){timer?.fireDate = .distantFuture;readinessTimer?.fireDate = .distantFuture}
// ACTUAL_TIMER_METHODS
// ACTUAL_DURATION_METHOD
// ACTUAL_STATE_METHOD
}
@main private enum Probe {
    @MainActor static func settle()async{for _ in 0..<60{await Task.yield()}}
    @MainActor static func requestEntered(_ manager:PacketTunnelManager,_ count:Int)async->Bool{
        for _ in 0..<1000 {if manager.replies.count>=count{return true};await Task.yield()}
        return false
    }
    @MainActor static func main()async{
        var failed:[String]=[];var checks=0
        func check(_ value:Bool,_ name:String){checks+=1;if !value{failed.append(name)}}
        func fresh()->(Host,PacketTunnelManager){let manager=PacketTunnelManager();let host=Host(manager);host.startTimer();host.parkTimers();return(host,manager)}
        func retire(_ host:Host,_ manager:PacketTunnelManager)async{host.stopTimer();manager.finishAll();await settle()}
        do{
            let(h,m)=fresh();await settle()
            check(m.replies.count==1,"immediate readiness request before a traffic tick")
            if !m.replies.isEmpty {
                h.previousTrafficSampleTime=99;h.previousTrafficUpload=7;h.previousTrafficDownload=9
                m.finish(0,"ready");await settle()
                check(h.events.last=="CONNECTED"&&h.readinessTimer==nil,"positive readiness publishes immediately and stops rapid polling")
                check(m.trafficRequests==0&&h.previousTrafficSampleTime==99&&h.previousTrafficUpload==7&&h.previousTrafficDownload==9,"readiness does not query stats or change rate baselines")
            }
            await retire(h,m)
        }
        do{
            let(h,m)=fresh();await settle()
            if !m.replies.isEmpty{
                h.timer?.fire();h.readinessTimer?.fire();await settle()
                check(m.replies.count==1,"regular and rapid polls share one in-flight request")
                m.finish(0,"waiting");await settle()
                check(!h.events.contains("CONNECTED")&&m.trafficRequests==0,"not-ready cannot connect or start traffic query")
                h.readinessTimer?.fire();await settle();h.timer?.fire();await settle()
                check(m.replies.count==2,"second held readiness still excludes regular overlap")
                m.finish(1,"ready");await settle()
                check(h.events.filter{$0=="CONNECTED"}.count==1,"one current positive reply publishes exactly once")
            }else{check(false,"shared-flight initial request missing")}
            await retire(h,m)
        }
        for kind in ["nil","malformed","error"]{
            let(h,m)=fresh();await settle()
            if !m.replies.isEmpty{
                m.finish(0,kind=="malformed" ? "not-ready" : nil,failure:kind=="error");await settle()
                check(!h.events.contains("CONNECTED")&&h.readinessTimer != nil,"\(kind) response stays connecting with bounded retry")
                h.readinessTimer?.fire();await settle();m.finish(1,"ready");await settle()
                check(h.events.last=="CONNECTED","\(kind) next real-ready reply recovers")
            }else{check(false,"\(kind) initial request missing")}
            await retire(h,m)
        }
        for mode in ["stop","replacement","date","proxy","reasserting"]{
            let(h,m)=fresh();await settle()
            if !m.replies.isEmpty{
                let next=PacketTunnelManager()
                switch mode {
                case "stop":h.stopTimer();m.status = .disconnected;m.connectedDate=nil
                case "replacement":h.packetTunnelManager=next
                case "date":m.connectedDate=Date(timeIntervalSince1970:200)
                case "proxy":h.proxyOnlyRunner.isRunning=true
                default:m.status = .reasserting
                }
                h.readinessTimer?.fire();h.parkTimers();await settle()
                check(m.replies.count==1&&next.replies.isEmpty,"\(mode) does not release another request's lease")
                let emissions=h.events.count;m.finish(0,"ready");await settle()
                check(h.events.count==emissions,"\(mode) late reply cannot emit CONNECTED")
                if ["stop","date","reasserting"].contains(mode){check(!m.forwardingReady,"\(mode) rejects stale forwarding-ready mutation")}
                if ["replacement","date"].contains(mode){
                    let current=mode=="replacement" ? next:m
                    h.readinessTimer?.fire();await settle()
                    let index=current.replies.count-1
                    check(index>=0,"\(mode) new owner can acquire after old lease release")
                    if index>=0{current.finish(index,"ready");await settle();check(h.events.last=="CONNECTED","\(mode) new owner ready publishes")}
                    current.finishAll()
                }else{check(h.readinessTimer==nil,"\(mode) rapid timer stops")}
            }else{check(false,"\(mode) initial request missing")}
            await retire(h,m)
        }
        do{
            let(h,m)=fresh();await settle()
            if !m.replies.isEmpty{
                m.finish(0,"waiting");await settle();h.time+=5_000_000_001;h.readinessTimer?.fire();await settle()
                check(h.readinessTimer==nil,"five-second expiry stops only rapid polling")
                h.startTimer();await settle()
                check(h.readinessTimer==nil&&m.replies.count==1,"same-owner repeated start cannot rearm expired rapid window")
                h.timer?.fire();await settle();check(m.replies.count==2,"ordinary one-second timer remains usable after expiry")
                m.finish(1,"ready");await settle();check(h.events.last=="CONNECTED","ordinary positive readiness emits without an extra Mac tick")
            }else{check(false,"expiry initial request missing")}
            await retire(h,m)
        }
        for oldReply in ["not-ready","error"]{
            let(h,m)=fresh();await settle()
            if !m.replies.isEmpty{
                h.stopTimer();h.startTimer();h.parkTimers();await settle()
                check(m.replies.count==2,"new timer generation starts its own readiness request")
                m.finish(1,"ready");await settle();let count=h.events.count
                m.finish(0,oldReply,failure:oldReply=="error");await settle()
                check(m.forwardingReady&&h.events.count==count,"same-date old generation \(oldReply) cannot overwrite newer true or publish")
            }else{check(false,"restart initial request missing")}
            await retire(h,m)
        }
        for reply in ["ready","not-ready","error"]{
            let m=PacketTunnelManager();let pending=Task{@MainActor in await m.refreshForwardingState()}
            guard await requestEntered(m,1) else {check(false,"actual manager request entered before release");continue}
            m.connectedDate=Date(timeIntervalSince1970:400);m.forwardingReady=reply != "ready"
            m.finish(0,reply,failure:reply=="error");await pending.value
            check(m.forwardingReady==(reply != "ready"),"actual manager ignores older-connection \(reply) assignment")
        }
#if OWNER_GUARD
        do{
            let m=PacketTunnelManager();var ownerCheckThreads:[Bool]=[]
            let pending=Task.detached {await m.refreshForwardingState {ownerCheckThreads.append(Thread.isMainThread);return true}}
            if await requestEntered(m,1){
                m.finish(0,"ready");await pending.value
                check(ownerCheckThreads==[true,true]&&m.forwardingReady,"detached caller performs both owner checks and assignment on MainActor")
            }else{check(false,"detached manager request entered before release")}
        }
#endif
        for name in failed{print("APPLE_READINESS_FAILURE="+name)}
#if IOS
        print("IOS_READINESS_CHECKS=\(checks);FAILURES=\(failed.count)")
#else
        print("MACOS_READINESS_CHECKS=\(checks);FAILURES=\(failed.count)")
#endif
        if !failed.isEmpty{exit(1)}
    }
}
