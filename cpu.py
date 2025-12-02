import sys
import json
import re

class Simulator:
    # ==================== 成员A负责：初始化 ====================

    def __init__(self):
        # 寄存器reg
        self.regs = {
            "rax": 0, "rcx": 0, "rdx": 0, "rbx": 0,
            "rsp": 0, "rbp": 0, "rsi": 0, "rdi": 0,
            "r8" : 0, "r9" : 0, "r10": 0, "r11": 0,
            "r12": 0, "r13": 0, "r14": 0
        }

        # 寄存器编号
        self.reg_names = [
            "rax", "rcx", "rdx", "rbx",
            "rsp", "rbp", "rsi", "rdi",
            "r8" , "r9" , "r10", "r11",
            "r12", "r13", "r14"
        ]

        # 条件码: ZF(零标志),SF(符号标志),OF(溢出标志)
        self.cc = {"ZF": 1, "SF": 0, "OF": 0}           # ZF初始设为1

        # 程序计数器
        self.pc = 0

        # 状态码: 1(AOK正常),2(HL正常终止),3(ADR地址错误),4(INS非法指令)
        self.stat = 1

        # Memory(字典存储，key为地址，value为字节)
        self.memory = {}

        # 状态历史
        self.history = []


    # ==================== 成员A负责：工具函数(内存那块用到了) ====================

    ## 将64位无符号整数转换成有符号整数
    def to_signed(self, val):
        val = val & 0xFFFFFFFFFFFFFFFF               # 只保留低64位
        if val >= (1 << 63):                
            return val - (1 << 64)                   # 负数转换

        return val 

    ## 将有符号整数转换为64位无符号整数
    def to_unsigned(self, val):
        return val & 0xFFFFFFFFFFFFFFFF
        

    # ==================== 成员A负责：内存管理 ====================

    ## 从内存中读取指定大小的数据: addr(起始地址),size(读取字节数)
    def read_memory(self, addr, size):
        if addr < 0:
            self.stat = 3                            # 地址错误
            return 0
        
        val = 0
        for i in range(size):
            byte_val = self.memory.get(addr + i, 0)
            val = val | (byte_val << (i * 8))        # 小端序
        
        return val                                   # 无符号整数                          

    ## 向内存写入指定大小的数据: addr(起始地址),val(写入的整数值),size(字节数)
    def write_memory(self, addr, val, size):
        if addr < 0:
            self.stat = 3                            # 地址错误
            return 0
        
        val = self.to_unsigned(val)                  # 调用工具函数，val转换成64位无符号整数
        for i in range(size):
            byte_val = (val >> (i * 8)) & 0xFF       # 分字节写入
            self.memory[addr + i] = byte_val         # 小端序


    # ==================== 成员A负责：文件解析 ====================

    ## 从标准输入读取并解析.yo格式文件
    def load_program(self):
        for line in sys.stdin:                       # 逐行读取                 
            line = line.split('|')[0].strip()        # 保留"|"左侧内容
            if not line or line.startswith('|'):
                continue                             # 跳过空行和注释行

            parts = line.split(':')                  # ":"作分隔符，把地址和字节序列分开
            if len(parts) < 2:
                continue                             # 跳过只有地址没有字节的行

            try:
                addr = int(parts[0].strip(), 16)     # 把地址字符串转换成int整数
            except ValueError:
                continue                             # 跳过格式错误的地址行

            # 得到":"右边的字节序列(16进制字符串)
            hex_bytes = parts[1].strip().replace(' ', '')

            # 每2个字符代表1个字节，依次写入内存
            for i in range(0, len(hex_bytes), 2):
                byte_str = hex_bytes[i:i+2]
                self.memory[addr] = int(byte_str, 16)# 将字节字符串转换成int整数
                addr += 1


    # ==================== 成员A负责：取指阶段 ====================

    ## 从 PC 指向的内存位置读取指令，返回icode(4bit指令码),ifun(4bit功能码),rA(源寄存器),rB(目的寄存器),valC(指令携带的常数),valP(下一条指令的地址)
    def fetch(self):
        if self.pc < 0 or self.pc not in self.memory:
            self.stat = 3                           # 地址错误
            return 0, 0, 0xF, 0xF, 0, self.pc       # 0xF表示无寄存器
        
        instr_byte = self.memory[self.pc]           # 读取指令字节
        icode = (instr_byte >> 4) & 0xF             # 高4位是指令码
        ifun = instr_byte & 0xF                     # 低4位是功能码
        
        valP = self.pc + 1                          # 下一个指令字节的地址
        rA = 0xF                                    # 默认无寄存器
        rB = 0xF
        valC = 0
        
        # 根据指令码解析后续字节
        if icode in [0, 1, 9]:                      # halt, nop, ret
            pass                                    # valP保持self.pc + 1即可
        elif icode in [2, 6, 7]:                    # rrmovq/cmovxx, opq, jxx
            if icode in [2, 6]:                     # 需要读取寄存器
                reg_byte = self.memory.get(valP, 0) 
                rA = (reg_byte >> 4) & 0xF          # 高4位
                rB = reg_byte & 0xF                 # 低4位
                valP += 1
            if icode == 7:                          # jxx需要8字节目标地址
                valC = self.read_memory(valP, 8)
                valP += 8
        elif icode == 3:                            # irmovq
            reg_byte = self.memory.get(valP, 0)
            rA = (reg_byte >> 4) & 0xF
            rB = reg_byte & 0xF
            valP += 1
            valC = self.read_memory(valP, 8)
            valP += 8
        elif icode in [4, 5]:                       # rmmovq, mrmovq
            reg_byte = self.memory.get(valP, 0)
            rA = (reg_byte >> 4) & 0xF
            rB = reg_byte & 0xF
            valP += 1
            valC = self.read_memory(valP, 8)        # 读取8字节偏移量
            valP += 8
        elif icode == 8:                            # call
            valC = self.read_memory(valP, 8)
            valP += 8
        elif icode in [0xA, 0xB]:                   # pushq, popq
            reg_byte = self.memory.get(valP, 0)
            rA = (reg_byte >> 4) & 0xF
            rB = reg_byte & 0xF
            valP += 1
        
        return icode, ifun, rA, rB, valC, valP


    # ==================== 成员A负责：译码辅助函数 ====================

    ## 译码阶段：获取寄存器的值
    def decode_registers(self, rA, rB):
        valA = 0
        valB = 0
        
        if rA != 0xF and rA < len(self.reg_names):  # 寄存器编号合理
            valA = self.regs[self.reg_names[rA]]
        
        if rB != 0xF and rB < len(self.reg_names):
            valB = self.regs[self.reg_names[rB]]
        
        return valA, valB




    # ==================== 成员B负责：指令分发逻辑 ====================
    def step(self):
        if self.stat!=1:
            return
        icode, ifun, rA, rB, valC, valP=self.fetch()
        if icode == 0:
            self.exec_halt()                       # 统一格式
        elif icode == 1:
            self.exec_nop(valP)                         # 统一格式
        elif icode == 2:
            self.exec_rrmovq(ifun, rA, rB, valP)
        elif icode == 3:
            self.exec_irmovq(rB, valC, valP)
        elif icode == 4:
            self.exec_rmmovq(rA, rB, valC, valP)
        elif icode == 5:
            self.exec_mrmovq(rA, rB, valC, valP)
        elif icode == 6:
            self.exec_opq(ifun, rA, rB, valP)
        elif icode == 7:
            self.exec_jxx(ifun, valC, valP)
        elif icode == 8:
            self.exec_call(valC, valP)
        elif icode == 9:
            self.exec_ret()         #用不到valP，前后保持一致
        elif icode == 0xA:          # pushq
            self.exec_pushq(rA, valP)
        elif icode == 0xB:          # popq
            self.exec_popq(rA, valP)
        else:
        # 非法指令
            self.stat = 4
        
        

    # ==================== 成员B负责：算术逻辑指令 ====================
    def update_cc(self, result_u, a_s, b_s, op):
        """
        更新条件码：
        - result_u：64bit 无符号运算结果
        - a_s / b_s：参与运算的两个有符号数
        - op: 'add' / 'sub' / 'and' / 'xor'
        """
        r = self.to_signed(result_u)
        self.cc["ZF"] = 1 if r == 0 else 0
        self.cc["SF"] = 1 if r < 0 else 0

        of = 0
        if op == "add":             # a + b 溢出：同号相加结果异号
            of = int((a_s > 0 and b_s > 0 and r < 0) or
                     (a_s < 0 and b_s < 0 and r >= 0))
        elif op == "sub":           # subq：rB <- rB - rA = b - a
            diff = r
            of = int((b_s > 0 and a_s < 0 and diff < 0) or
                     (b_s < 0 and a_s > 0 and diff >= 0))
        else:
            of = 0
        self.cc["OF"] = of
    
    
    def exec_opq(self, ifun, rA, rB, valP):
        valA, valB = self.decode_registers(rA, rB)
        a = self.to_signed(valA)
        b = self.to_signed(valB)
        
        if ifun == 0x0:      # addq
            res = a + b
            op = "add"
        elif ifun == 0x1:    # subq: rB <- rB - rA
            res = b - a
            op = "sub"
        elif ifun == 0x2:    # andq
            res = a & b
            op = "and"
        elif ifun == 0x3:    # xorq
            res = a ^ b
            op = "xor"
        else:
            self.stat = 4
            return
        
        res_u = self.to_unsigned(res)
        self.update_cc(res_u, a, b, op)# 更新条件码

        self.regs[self.reg_names[rB]] = res_u       #修改错误，rB是数值，得通过reg_names获得其字符串
        self.pc = valP
        
    # ==================== 成员B负责：数据传送指令 ====================
    def exec_rrmovq(self, ifun, rA, rB, valP):
        regA=self.reg_names[rA]
        regB=self.reg_names[rB]
        if regA is None or regB is None:
            self.stat = 4
            return
        if self.check_condition(ifun):
            self.regs[regB] = self.to_unsigned(self.regs[regA])

        self.pc = valP
        

    def exec_irmovq(self, rB, valC, valP):
        regB = self.reg_names[rB]
        if regB is None:
            self.stat = 4
            return

        self.regs[regB] = self.to_unsigned(valC)        # 立即数 -> 寄存器，不影响条件码
        self.pc = valP

    def exec_rmmovq(self, rA, rB, valC, valP):
        regA = self.reg_names[rA]
        regB = self.reg_names[rB]
        if regA is None or regB is None:
            self.stat = 4
            return

        valA = self.regs[regA]
        base = self.to_signed(self.regs[regB])
        offset = self.to_signed(valC)
        addr = base + offset

        self.write_memory(addr, valA, 8)
        self.pc = valP
        
    def exec_mrmovq(self, rA, rB, valC, valP):
        regA = self.reg_names[rA]
        regB = self.reg_names[rB]
        if regA is None or regB is None:
            self.stat = 4
            return

        base = self.to_signed(self.regs[regB])
        offset = self.to_signed(valC)
        addr = base + offset

        val = self.read_memory(addr, 8)
        self.regs[regA] = self.to_unsigned(val)
        self.pc = valP

    # ==================== 成员A负责：jxx ====================

    def check_condition(self, ifun):
        if ifun == 0:                              # jmp:无条件
            return True
        elif ifun == 1:                            # jle:(<=) (SF^OF)|ZF
            return (self.cc["SF"] ^ self.cc["OF"]) | self.cc["ZF"]
        elif ifun == 2:                            # jl(<): SF^OF
            return self.cc["SF"] ^ self.cc["OF"]
        elif ifun == 3:                            # je(==): ZF
            return self.cc["ZF"]
        elif ifun == 4:                            # jne(!=): ~ZF
            return not self.cc["ZF"]
        elif ifun == 5:                            # jge(>=): ~(SF^OF)
            return not (self.cc["SF"] ^ self.cc["OF"])
        elif ifun == 6:                            # jg(>): ~(SF^OF)&~ZF
            return (not (self.cc["SF"] ^ self.cc["OF"])) and (not self.cc["ZF"])
        return False

    def exec_jxx(self, ifun, valC, valP):           # 成员A完成的
        if_jump = self.check_condition(ifun)

        if if_jump:
            self.pc = valC
        else:
            self.pc = valP
    # ==================== 成员C负责：控制流指令 ====================

    def exec_call(self, valC, valP):
        self.regs["rsp"] -= 8
        self.write_memory(self.regs["rsp"], valP, 8)
        self.pc = valC

    def exec_ret(self):
        self.pc = self.read_memory(self.regs["rsp"], 8)             #用不到valP，可删除     
        self.regs["rsp"] += 8

    # ==================== 成员C负责：栈操作指令 ====================
    def exec_pushq(self, rA, valP):
        val = self.regs[self.reg_names[rA]]
        self.regs["rsp"] -= 8
        self.write_memory(self.regs["rsp"], val, 8)
        if self.stat == 1:                               # 注意到prog10出错，当前面程序已经出错，stat != 1时，不应该继续函数
            self.pc = valP
       

    def exec_popq(self, rA, valP):
        val = self.read_memory(self.regs["rsp"], 8) 
        self.regs["rsp"] += 8
        self.regs[self.reg_names[rA]] = val
        self.pc = valP

    # ==================== 成员C负责：其他指令 ====================
    def exec_halt(self):
        self.stat = 2;

    def exec_nop(self, valP):
        self.pc = valP

    # ==================== 成员C负责：状态输出 ====================
    def get_state(self):
        memory_set = set((k // 8) * 8 for k in self.memory.keys())  #注意到poptest测试中memory出现大量错误，
        memory_output = {}
        for addr in memory_set:
            val = self.read_memory(addr, 8)
            val = self.to_signed(val)                               #注意到正确答案中都是有符号数，而直接输出存在无符号数
            if val != 0:
                memory_output[str(addr)] = val
    
        regs_signed = {}                                            #以j-cc测试为例，注意到reg错误答案有一个巨大的无符号数
        for reg_name, reg_val in self.regs.items():
            regs_signed[reg_name] = self.to_signed(reg_val)

        return {
            "CC": self.cc.copy(),
            "MEM": memory_output,
            "PC": self.pc,
            "REG": regs_signed,
            "STAT": self.stat
        }

    # ==================== 成员C负责：主控制流程 ====================
    def run(self):
        self.load_program()
        while self.stat == 1:
            self.step()
            self.history.append(self.get_state())
        
        print(json.dumps(self.history))


if __name__ == "__main__":
    sim = Simulator()
    sim.run()
