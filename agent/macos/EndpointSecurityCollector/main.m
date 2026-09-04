#import <EndpointSecurity/EndpointSecurity.h>
#import <Foundation/Foundation.h>
#import <bsm/libbsm.h>
#import <signal.h>
#import <sys/wait.h>

static es_client_t *client;
static NSFileHandle *output;
static uint64_t lastSequence;
static uint64_t lastGlobalSequence;

static NSString *Token(es_string_token_t token) {
    if (token.length == 0 || token.data == NULL) return nil;
    return [[NSString alloc] initWithBytes:token.data length:token.length encoding:NSUTF8StringEncoding];
}

static void Emit(const es_message_t *message, NSString *kind, const es_process_t *process, NSNumber *exitCode) {
    pid_t pid = audit_token_to_pid(process->audit_token);
    pid_t parent = audit_token_to_pid(process->parent_audit_token);
    uid_t uid = audit_token_to_euid(process->audit_token);
    NSMutableDictionary *record = [@{
        @"kind": kind, @"pid": @(pid), @"parentPid": @(parent), @"userId": [@(uid) stringValue],
        @"observedAt": [[NSDate date] descriptionWithLocale:@{NSLocaleIdentifier:@"en_US_POSIX"}],
        @"startKey": [NSString stringWithFormat:@"%u:%u:%llu", pid, audit_token_to_pidversion(process->audit_token), message->seq_num],
        @"sourceEventId": [NSString stringWithFormat:@"endpoint-security:%llu", message->seq_num],
        @"sequence": @(message->seq_num), @"path": Token(process->executable->path) ?: [NSNull null],
        @"platformBinary": @(process->is_platform_binary), @"signingId": Token(process->signing_id) ?: [NSNull null],
        @"teamId": Token(process->team_id) ?: [NSNull null], @"signingFlags": @(process->codesigning_flags)
    } mutableCopy];
    if (exitCode) record[@"exitCode"] = exitCode;
    if (lastSequence && message->seq_num > lastSequence + 1) record[@"sequenceGap"] = @(message->seq_num - lastSequence - 1);
    lastSequence = message->seq_num;
    if (message->version >= 4) {
        record[@"globalSequence"] = @(message->global_seq_num);
        if (lastGlobalSequence && message->global_seq_num > lastGlobalSequence + 1) record[@"globalSequenceGap"] = @(message->global_seq_num - lastGlobalSequence - 1);
        lastGlobalSequence = message->global_seq_num;
    }
    NSData *json = [NSJSONSerialization dataWithJSONObject:record options:0 error:nil];
    [output writeData:json]; [output writeData:[@"\n" dataUsingEncoding:NSUTF8StringEncoding]];
}

static void Shutdown(int signalNumber) {
    (void)signalNumber;
    if (client) { es_unsubscribe_all(client); es_delete_client(client); client = NULL; }
    [output synchronizeFile]; exit(0);
}

int main(void) {
    @autoreleasepool {
        NSString *path = [[[NSProcessInfo processInfo] environment] objectForKey:@"PLATFORM_MACOS_ES_JSON_PATH"] ?: @"/Library/Application Support/OpenSecurityPlatform/process-events.jsonl";
        [[NSFileManager defaultManager] createDirectoryAtPath:[path stringByDeletingLastPathComponent] withIntermediateDirectories:YES attributes:@{NSFilePosixPermissions:@0600} error:nil];
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) [[NSData data] writeToFile:path atomically:YES];
        output = [NSFileHandle fileHandleForWritingAtPath:path]; [output seekToEndOfFile];
        es_new_client_result_t result = es_new_client(&client, ^(es_client_t *c, const es_message_t *message) {
            (void)c;
            @autoreleasepool {
                if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC) {
                    const es_process_t *target = message->event.exec.target;
                    Emit(message, @"started", target, nil);
                } else if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXIT) {
                    int status = message->event.exit.stat;
                    NSNumber *code = WIFEXITED(status) ? @(WEXITSTATUS(status)) : @(-WTERMSIG(status));
                    Emit(message, @"exited", message->process, code);
                }
            }
        });
        if (result != ES_NEW_CLIENT_RESULT_SUCCESS) { fprintf(stderr, "es_new_client failed: %d\n", result); return 2; }
        es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT };
        if (es_subscribe(client, events, 2) != ES_RETURN_SUCCESS) { fprintf(stderr, "es_subscribe failed\n"); es_delete_client(client); return 3; }
        signal(SIGTERM, Shutdown); signal(SIGINT, Shutdown);
        dispatch_main();
    }
}
