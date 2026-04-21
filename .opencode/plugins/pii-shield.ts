import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

function scanForPII(content: Record<string, unknown>, projectDir: string): { detected: boolean; reason?: string } {
  try {
    const pythonScriptPath = path.join(projectDir, 'pii_shield.py');
    
    if (!fs.existsSync(pythonScriptPath)) {
      console.error('PII Shield: Python script not found at', pythonScriptPath);
      return { detected: false };
    }

    const args = content.hook_event_name ? [pythonScriptPath, '--hook-mode', 'stdin'] : [pythonScriptPath, 'hook'];

    const result = spawnSync('python3', args, {
      input: JSON.stringify(content),
      maxBuffer: 10 * 1024 * 1024,
      timeout: 5000,
      encoding: 'utf-8',
    });

    if (args.includes('--hook-mode')) {
      if (result.status === 0) {
        try {
          const output = JSON.parse(result.stdout || '{}');
          if (output.hookSpecificOutput && output.hookSpecificOutput.permissionDecision === 'deny') {
            return { 
              detected: true, 
              reason: output.hookSpecificOutput.permissionDecisionReason 
            };
          } else if (output.replacementResult !== undefined) {
            return { 
              detected: true, 
              reason: `REPLACEMENT:${output.replacementResult}` 
            };
          }
          return { detected: false };
        } catch (e) {
          return { detected: false };
        }
      }
    } else {
      if (result.status === 2) {
        const errorMessage = result.stderr?.trim() || 'PII detected and blocked';
        return { detected: true, reason: errorMessage };
      }

      if (result.status === 1) {
        console.error('PII Shield error:', result.stderr);
        return { detected: false };
      }

      if (result.stderr && result.stderr.toLowerCase().includes('detected')) {
        return { detected: true, reason: result.stderr.trim() };
      }
    }

    return { detected: false };
  } catch (error) {
    console.error('PII Shield scan error:', error);
    return { detected: false };
  }
}

export const PIIShield = async ({ project, client, $, directory, worktree }: {
  project?: unknown;
  client?: unknown;
  $?: unknown;
  directory?: string;
  worktree?: unknown;
}) => {
  const projectDir = directory || process.cwd();
  
  return {
    'tool.execute.before': async (input: { tool: string }, output: { args: Record<string, unknown> }) => {
      const toolName = input?.tool?.toLowerCase() || '';
      
      if (!['read', 'bash', 'grep'].includes(toolName)) {
        return;
      }

      let contentToScan: Record<string, unknown> = { tool: toolName };
      contentToScan['hook_event_name'] = 'PreToolUse';
      contentToScan['regex_only'] = true;
      contentToScan['tool'] = toolName;
      
      const toolInput: Record<string, unknown> = {};
      
      switch (toolName) {
        case 'read':
          toolInput.filePath = output?.args?.filePath || output?.args?.path || '';
          break;
        case 'bash':
          toolInput.command = output?.args?.command || output?.args?.args || '';
          break;
        case 'grep':
          toolInput.pattern = output?.args?.pattern || '';
          toolInput.path = output?.args?.path || '';
          break;
      }
      
      contentToScan['tool_input'] = toolInput;

      const scanResult = scanForPII(contentToScan, projectDir);

      if (scanResult.detected) {
        throw new Error(`PII Shield: ${scanResult.reason}`);
      }
    },
    
    'tool.execute.after': async (input: { tool: string }, output: Record<string, unknown>) => {
      const toolName = input?.tool?.toLowerCase() || '';
      
      let contentToScan: Record<string, unknown> = { 
        tool: toolName,
        hook_event_name: 'PostToolResult',
        regex_only: false
      };

      if (toolName === 'read') {
        let fileContent: string | undefined;
        
        if (typeof output?.result === 'string') {
          fileContent = output.result;
        } else if (typeof output?.content === 'string') {
          fileContent = output.content;
        } else if (typeof output?.output === 'string') {
          fileContent = output.output;
        } else if (typeof output?.result === 'object' && output.result && typeof (output.result as Record<string, unknown>).content === 'string') {
          fileContent = (output.result as Record<string, unknown>).content as string;
        } else if (typeof output === 'string') {
          fileContent = output;
        }

        if (fileContent) {
          contentToScan['result'] = { output: fileContent };
        }
      } else if (toolName === 'bash') {
        const stdout = typeof output?.stdout === 'string' ? output.stdout : 
                       typeof output?.result === 'object' && output.result ? 
                          (output.result as Record<string, unknown>).stdout as string || '' : '';
        const stderr = typeof output?.stderr === 'string' ? output.stderr : 
                       typeof output?.result === 'object' && output.result ? 
                          (output.result as Record<string, unknown>).stderr as string || '' : '';

        if (stdout || stderr) {
          contentToScan['result'] = { 
            stdout: stdout,
            stderr: stderr
          };
        }
      } else if (toolName === 'grep') {
        let grepOutput: string | undefined;
        
        if (typeof output?.result === 'string') {
          grepOutput = output.result;
        } else if (typeof output?.content === 'string') {
          grepOutput = output.content;
        } else if (typeof output?.output === 'string') {
          grepOutput = output.output;
        }
        
        if (grepOutput) {
          contentToScan['result'] = { output: grepOutput };
        }
      }

      if ((toolName === 'read' || toolName === 'bash' || toolName === 'grep') && 
          contentToScan.result) {
        
        const scanResult = scanForPII(contentToScan, projectDir);
        
        if (scanResult.detected) {
          if (scanResult.reason && scanResult.reason.includes('REPLACEMENT:')) {
            const replacementContent = scanResult.reason.replace('REPLACEMENT:', '');
            return { result: replacementContent };
          }
          
          console.warn(`PII Shield: Potential PII detected in ${toolName} output`);
        }
      }
    },
  };
};

export default PIIShield;
