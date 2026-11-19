// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

#import <Cocoa/Cocoa.h>

int main(int argc, char *argv[])
{
    NSString *appId = [NSBundle.mainBundle objectForInfoDictionaryKey:@"com.wireguard.macos.app_id"];
    NSString *appGroupId = [NSBundle.mainBundle objectForInfoDictionaryKey:@"com.wireguard.macos.app_group_id"];
    if (!appId || !appGroupId)
        return 1;

    // SMLoginItemSetEnabled launches this helper immediately, including while
    // the main app is already running. Do not re-open (or hide) it in that case.
    if ([NSRunningApplication runningApplicationsWithBundleIdentifier:appId].count > 0)
        return 0;

    NSURL *containerUrl = [[NSFileManager defaultManager] containerURLForSecurityApplicationGroupIdentifier:appGroupId];
    if (!containerUrl)
        return 2;
    uint64_t now = clock_gettime_nsec_np(CLOCK_UPTIME_RAW);
    if (![[NSData dataWithBytes:&now length:sizeof(now)] writeToURL:[containerUrl URLByAppendingPathComponent:@"login-helper-timestamp.bin"] atomically:YES])
        return 3;

    NSCondition *condition = [[NSCondition alloc] init];
    NSURL *appURL = [NSWorkspace.sharedWorkspace URLForApplicationWithBundleIdentifier:appId];
    if (!appURL)
        return 4;
    NSWorkspaceOpenConfiguration *openConfiguration = [NSWorkspaceOpenConfiguration configuration];
    openConfiguration.activates = NO;
    openConfiguration.addsToRecentItems = NO;
    openConfiguration.hides = YES;
    __block BOOL finished = NO;
    [NSWorkspace.sharedWorkspace openApplicationAtURL:appURL configuration:openConfiguration completionHandler:^(NSRunningApplication * _Nullable app, NSError * _Nullable error) {
        [condition lock];
        finished = YES;
        [condition signal];
        [condition unlock];
    }];
    [condition lock];
    if (!finished)
        [condition waitUntilDate:[NSDate dateWithTimeIntervalSinceNow:10]];
    [condition unlock];
    return 0;
}
