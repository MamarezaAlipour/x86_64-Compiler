#pragma once

#include <cstring>
#include <memory>
#include <string>

#include "x86_64_compiler/bytearray.hpp"
#include "x86_64_compiler/function.hpp"

namespace x86_64 {

	namespace detail {

		constexpr int8_t NOREG = -1;

		enum class Size
		{
			None,
			Byte,
			Word,
			Dword,
			Qword,
		};

		enum ByteReg
		{
			AL,
			CL,
			DL,
			BL,
			AH,
			CH,
			DH,
			BH,
		};

		enum WordReg
		{
			AX,
			CX,
			DX,
			BX,
			SP,
			BP,
			SI,
			DI,
		};

		enum DwordReg
		{
			EAX,
			ECX,
			EDX,
			EBX,
			ESP,
			EBP,
			ESI,
			EDI,
		};

		enum QwordReg
		{
			RAX,
			RCX,
			RDX,
			RBX,
			RSP,
			RBP,
			RSI,
			RDI,
			R8,
			R9,
			R10,
			R11,
			R12,
			R13,
			R14,
			R15,
			RIP,
		};

		struct RegRef
		{
		public: // methods
			constexpr RegRef()
				: size{ Size::None }
				, reg{ NOREG }
			{
			}

			constexpr RegRef(ByteReg reg)
				: size{ Size::Byte }
				, reg{ static_cast<int8_t>(reg) }
			{
			}

			constexpr RegRef(WordReg reg)
				: size{ Size::Word }
				, reg{ static_cast<int8_t>(reg) }
			{
			}

			constexpr RegRef(DwordReg reg)
				: size{ Size::Dword }
				, reg{ static_cast<int8_t>(reg) }
			{
			}

			constexpr RegRef(QwordReg reg)
				: size{ Size::Qword }
				, reg{ static_cast<int8_t>(reg) }
			{
			}

			bool operator==(RegRef const& ref) const;
			bool operator!=(RegRef const& ref) const;

		public: // fields
			Size size;
			int8_t reg;
		};

	} // namespace detail

	constexpr detail::RegRef NOREG;

	constexpr detail::RegRef AL(detail::AL);
	constexpr detail::RegRef CL(detail::CL);
	constexpr detail::RegRef DL(detail::DL);
	constexpr detail::RegRef BL(detail::BL);
	constexpr detail::RegRef AH(detail::AH);
	constexpr detail::RegRef CH(detail::CH);
	constexpr detail::RegRef DH(detail::DH);
	constexpr detail::RegRef BH(detail::BH);

	constexpr detail::RegRef AX(detail::AX);
	constexpr detail::RegRef CX(detail::CX);
	constexpr detail::RegRef DX(detail::DX);
	constexpr detail::RegRef BX(detail::BX);
	constexpr detail::RegRef SP(detail::SP);
	constexpr detail::RegRef BP(detail::BP);
	constexpr detail::RegRef SI(detail::SI);
	constexpr detail::RegRef DI(detail::DI);

	constexpr detail::RegRef EAX(detail::EAX);
	constexpr detail::RegRef ECX(detail::ECX);
	constexpr detail::RegRef EDX(detail::EDX);
	constexpr detail::RegRef EBX(detail::EBX);
	constexpr detail::RegRef ESP(detail::ESP);
	constexpr detail::RegRef EBP(detail::EBP);
	constexpr detail::RegRef ESI(detail::ESI);
	constexpr detail::RegRef EDI(detail::EDI);

	constexpr detail::RegRef RAX(detail::RAX);
	constexpr detail::RegRef RCX(detail::RCX);
	constexpr detail::RegRef RDX(detail::RDX);
	constexpr detail::RegRef RBX(detail::RBX);
	constexpr detail::RegRef RSP(detail::RSP);
	constexpr detail::RegRef RBP(detail::RBP);
	constexpr detail::RegRef RSI(detail::RSI);
	constexpr detail::RegRef RDI(detail::RDI);
	constexpr detail::RegRef R8(detail::R8);
	constexpr detail::RegRef R9(detail::R9);
	constexpr detail::RegRef R10(detail::R10);
	constexpr detail::RegRef R11(detail::R11);
	constexpr detail::RegRef R12(detail::R12);
	constexpr detail::RegRef R13(detail::R13);
	constexpr detail::RegRef R14(detail::R14);
	constexpr detail::RegRef R15(detail::R15);
	constexpr detail::RegRef RIP(detail::RIP);

	class Compiler final
	{
	public: // types
		using RegRef = detail::RegRef;

		struct MemRef
		{
		public: // methods
			MemRef(int8_t scale, RegRef const& index, RegRef const& base);

			MemRef operator+(int64_t offset) const;
			MemRef operator-(int64_t offset) const;

		private: // methods
			MemRef(MemRef const& ref, int64_t disp);

		public: // fields
			int8_t scale;
			RegRef index;
			RegRef base;
			int64_t disp;
			bool disp_specified;
		};

		friend MemRef operator+(int64_t offset, MemRef const& ref);

		struct SymRef
		{
		public: // types
			enum class Type
			{
				Abs,
				Rel,
			};

		public: // methods
			SymRef(Type type, std::string const& name);
			SymRef(SymRef const& ref);
			SymRef(SymRef&& ref);

			SymRef& operator=(SymRef const& ref);
			SymRef& operator=(SymRef&& ref);

			~SymRef();

			SymRef operator+(int64_t offset) const;
			SymRef operator-(int64_t offset) const;

		private: // methods
			SymRef(const SymRef& ref, int64_t offset);

		public: // fields
			Type type;
			const char* name;
			int64_t offset;
		};

		friend SymRef operator+(int64_t offset, SymRef const& ref);

		struct Ref
		{
		public: // types
			enum class Type
			{
				Reg,
				Mem,
			};

		public: // methods
			Ref(RegRef const& ref);
			Ref(MemRef const& ref);
			Ref(Ref const& ref);
			Ref(Ref&& ref);

			Ref& operator=(Ref const& ref);
			Ref& operator=(Ref&& ref);

			Ref operator+(int64_t offset) const;

		public: // fields
			Type type;

			union
			{
				RegRef reg;
				MemRef mem;
			};
		};

		friend Ref operator+(int64_t offset, Ref const& ref);

	public: // methods
		Compiler();
		~Compiler();

		void reset();

		void rdata(std::string const& name, uint8_t const* data, std::size_t size);

		template <class T>
		void rdata(std::string const& name, T value);

		void data(std::string const& name, uint8_t const* data, std::size_t size);

		template <class T>
		void data(std::string const& name, T value);

		void bss(std::string const& name, std::size_t size);

		const ByteArray& getCode() const;

		RegRef reg(RegRef const& reg) const;

		MemRef mem(int64_t disp) const;
		MemRef mem(RegRef const& reg) const;
		MemRef mem(RegRef const& index, int8_t scale) const;
		MemRef mem(RegRef const& base, RegRef const& index, int8_t scale) const;

		SymRef abs(std::string const& name);
		SymRef rel(std::string const& name);

		void relocate(std::string const& name, int64_t value);

		void constant(uint8_t value);
		void constant(uint16_t value);
		void constant(uint32_t value);
		void constant(uint64_t value);
		void constant(double value);

		void add(const Ref& src, Ref const& dst);
		void addb(uint8_t imm, Ref const& dst);
		void addw(uint16_t imm, Ref const& dst);
		void addl(uint32_t imm, Ref const& dst);
		void addq(uint64_t imm, Ref const& dst);

		void call(int32_t disp);
		void callw(int16_t disp);
		void callq(int32_t disp);
		void call(Ref const& ref);
		void callw(Ref const& ref);
		void callq(Ref const& ref);
		void lcall(Ref const& ref);
		void lcallw(Ref const& ref);
		void lcalll(Ref const& ref);
		void call(SymRef const& ref);
		void lcall(SymRef const& ref);

		void enter(uint16_t imm16, uint8_t imm8);
		void enterw(uint16_t imm16, uint8_t imm8);
		void enterq(uint16_t imm16, uint8_t imm8);

		void lea(MemRef const& mem_ref, RegRef const& reg_ref);
		void lea(SymRef const& sym_ref, RegRef const& reg_ref);

		void leave();
		void leavew();
		void leaveq();

		void mov(Ref const& src, Ref const& dst);
		void mov(SymRef const& src, RegRef const& dst);
		void mov(RegRef const& src, SymRef const& dst);
		void movb(uint8_t imm, Ref const& dst);
		void movw(uint16_t imm, Ref const& dst);
		void movl(uint32_t imm, Ref const& dst);
		void movl(SymRef const& imm, Ref const& dst);
		void movq(uint64_t imm, Ref const& dst);

		void nop();

		void pop(RegRef const& ref);
		void popw(MemRef const& ref);
		void popq(MemRef const& ref);

		void push(uint32_t imm);
		void pushw(uint16_t imm);
		void pushq(uint32_t imm);
		void push(RegRef const& ref);
		void pushw(MemRef const& ref);
		void pushq(MemRef const& ref);
		void pushw(SymRef const& ref);
		void pushq(SymRef const& ref);

		void ret(uint16_t imm);
		void ret();
		void lret(uint16_t imm);
		void lret();

		void sub(Ref const& src, Ref const& dst);
		void subb(uint8_t imm, Ref const& dst);
		void subw(uint16_t imm, Ref const& dst);
		void subl(uint32_t imm, Ref const& dst);
		void subq(uint64_t imm, Ref const& dst);

	private: // types
		class Impl;

	private: // fields
		std::unique_ptr<Impl> m_impl;
	};

	template <class T>
	void Compiler::rdata(std::string const& name, T value)
	{
		rdata(name, reinterpret_cast<const uint8_t*>(&value), sizeof(value));
	}

	template <>
	inline void Compiler::rdata(std::string const& name, char const* value)
	{
		rdata(name, reinterpret_cast<const uint8_t*>(&value), strlen(value));
	}

	template <class T>
	void Compiler::data(std::string const& name, T value)
	{
		data(name, reinterpret_cast<uint8_t const*>(&value), sizeof(value));
	}

	template <>
	inline void Compiler::data(std::string const& name, char const* value)
	{
		data(name, reinterpret_cast<uint8_t const*>(&value), strlen(value));
	}

} // namespace x86_64
