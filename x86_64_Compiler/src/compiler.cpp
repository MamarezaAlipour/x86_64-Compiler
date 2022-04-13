#include "x86_64_compiler/compiler.hpp"
#include <cmath>
#include <limits>
#include <map>

namespace x86_64 {

	constexpr uint8_t c_mod_disp0 = 0;
	constexpr uint8_t c_mod_disp8 = 1;
	constexpr uint8_t c_mod_disp32 = 2;
	constexpr uint8_t c_mod_reg = 3;

	constexpr uint8_t c_x86_mask = 7;

	constexpr uint8_t c_operand_size_override_prefix = 0x66;
	constexpr uint8_t c_address_size_override_prefix = 0x67;

	constexpr uint8_t c_opcode_field_w = 1 << 0;
	constexpr uint8_t c_opcode_field_d = 1 << 1;

	constexpr uint8_t c_rex = 0x40;

	constexpr uint8_t c_rex_field_b = 1 << 0;
	constexpr uint8_t c_rex_field_x = 1 << 1;
	constexpr uint8_t c_rex_field_r = 1 << 2;
	constexpr uint8_t c_rex_field_w = 1 << 3;

	class Compiler::Impl final
	{
	private: // types
		using RegRef = detail::RegRef;
		using Size = detail::Size;

		using MemRef = Compiler::MemRef;
		using SymRef = Compiler::SymRef;
		using Ref = Compiler::Ref;

		struct Imm
		{
		public: // methods
			Imm(uint8_t value);
			Imm(uint16_t value);
			Imm(uint32_t value);
			Imm(uint64_t value);

		public: // fields
			Size size;

			union
			{
				uint8_t byte;
				uint16_t word;
				uint32_t dword;
				uint64_t qword;
			};
		};

		struct Symbol
		{
			std::string base_symbol;
			std::size_t offset;
		};

		enum SectionID
		{
			TEXT = 1,
			DATA,
			BSS,
			RDATA,
			EDATA,
			IDATA,
			RELOC,
		};

		struct Reloc
		{
			std::string name;
			SymRef::Type type;
			int64_t offset;
		};

	public: // methods
		void reset();

		void rdata(std::string const& name, uint8_t const* data, std::size_t size);
		void data(std::string const& name, uint8_t const* data, std::size_t size);
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

		void sub(const Ref& src, Ref const& dst);
		void subb(uint8_t imm, Ref const& dst);
		void subw(uint16_t imm, Ref const& dst);
		void subl(uint32_t imm, Ref const& dst);
		void subq(uint64_t imm, Ref const& dst);

	private: // methods
		void add(Imm const& imm, Ref const& dst);
		void mov(Imm const& imm, Ref const& dst);
		void push(Imm const& imm);
		void sub(Imm const& imm, Ref const& dst);

		void instr(uint8_t opcode, Ref const& op1, Ref const& dst);
		void instr(uint8_t opcode, int8_t reg, Size size, Ref const& rm_ref);
		void instr_no_w(uint8_t opcode, int8_t reg, Size size, Ref const& rm_ref);
		void instr(uint8_t opcode, int8_t ext, Imm const& imm, Ref const& dst);

		void genREXPrefix(
			int8_t const& reg,
			Size size,
			int8_t const& index,
			int8_t const& base);

		void genRef(int8_t reg, Ref const& ref);
		void genRef(int8_t reg, RegRef const& reg_ref);
		void genRef(int8_t reg, MemRef const& mem_ref);
		void genSIB(MemRef const& mem_ref);

		void genCompositeByte(uint8_t a, uint8_t b, uint8_t c);

		template <class T>
		void gen(T const& value);

		void genb(uint8_t);
		void genw(uint16_t);
		void genl(uint32_t);
		void genq(uint64_t);

		const ByteArray& section(SectionID id) const;
		ByteArray& section(SectionID id);

		bool isSectionDefined(SectionID id) const;
		std::size_t sectionSize(SectionID id) const;

		bool isSymbolDefined(std::string const& name) const;

		void pushSymbol(
			std::string const& name,
			std::string const& base_symbol,
			std::size_t offset);

		void pushReloc(Reloc const& reloc);

	public:
		template <class T>
		typename std::enable_if<std::is_signed<T>::value, bool>::type isByte(
			T value)
		{
			return value >= INT8_MIN && value <= INT8_MAX;
		}

		template <class T>
		typename std::enable_if<!std::is_signed<T>::value, bool>::type isByte(
			T value)
		{
			return value <= INT8_MAX;
		}

		template <class T>
		typename std::enable_if<std::is_signed<T>::value, bool>::type isDword(
			T value)
		{
			return value >= INT32_MIN && value <= INT32_MAX;
		}

		template <class T>
		typename std::enable_if<!std::is_signed<T>::value, bool>::type isDword(
			T value)
		{
			return value <= INT32_MAX;
		}

	private: // fields
		std::map<SectionID, ByteArray> m_sections;
		std::map<std::string, Symbol> m_symbols;
		std::vector<Reloc> m_relocs;
	};

	template <class T>
	void Compiler::Impl::gen(T const& value)
	{
		section(TEXT).push(value);
	}

	template <>
	inline void Compiler::Impl::gen(Imm const& imm)
	{
		switch (imm.size)
		{
		case Size::Byte:
			gen(imm.byte);
			break;

		case Size::Word:
			gen(imm.word);
			break;

		case Size::Dword:
			gen(imm.dword);
			break;

		case Size::Qword:
			gen(imm.qword);
			break;

		default:
			break;
		}
	}

	bool detail::RegRef::operator==(detail::RegRef const& ref) const
	{
		return size == ref.size && reg == ref.reg;
	}

	bool detail::RegRef::operator!=(detail::RegRef const& ref) const
	{
		return !(*this == ref);
	}

	Compiler::MemRef::MemRef(int8_t scale, RegRef const& index, RegRef const& base)
		: scale{ scale }
		, index{ index }
		, base{ base }
		, disp{ 0 }
		, disp_specified{ false }
	{
	}

	Compiler::MemRef Compiler::MemRef::operator-(int64_t offset) const
	{
		return MemRef(*this, disp - offset);
	}

	Compiler::MemRef::MemRef(const MemRef& ref, int64_t disp)
		: scale{ ref.scale }
		, index{ ref.index }
		, base{ ref.base }
		, disp{ disp }
		, disp_specified{ true }
	{
	}

	Compiler::MemRef Compiler::MemRef::operator+(int64_t offset) const
	{
		return MemRef(*this, disp + offset);
	}

	Compiler::MemRef operator+(int64_t offset, const Compiler::MemRef& ref)
	{
		return ref + offset;
	}

	Compiler::SymRef::SymRef(Type type, std::string const& name)
		: type{ type }
		, name{ strdup(name.c_str()) }
		, offset{ 0 }
	{
	}

	Compiler::SymRef::SymRef(SymRef const& ref)
		: name{ nullptr }
	{
		*this = ref;
	}

	Compiler::SymRef::SymRef(SymRef&& ref)
		: name{ nullptr }
	{
		*this = std::move(ref);
	}

	Compiler::SymRef& Compiler::SymRef::operator=(SymRef const& ref)
	{
		delete name;

		type = ref.type;
		name = strdup(ref.name);
		offset = ref.offset;

		return *this;
	}

	Compiler::SymRef& Compiler::SymRef::operator=(SymRef&& ref)
	{
		delete name;

		type = ref.type;
		name = ref.name;
		offset = ref.offset;

		ref.name = nullptr;

		return *this;
	}

	Compiler::SymRef::~SymRef()
	{
		delete name;
	}

	Compiler::SymRef Compiler::SymRef::operator+(int64_t offset) const
	{
		return SymRef(*this, this->offset + offset);
	}

	Compiler::SymRef Compiler::SymRef::operator-(int64_t offset) const
	{
		return SymRef(*this, this->offset - offset);
	}

	Compiler::SymRef::SymRef(SymRef const& ref, int64_t offset)
		: type{ ref.type }
		, name{ strdup(ref.name) }
		, offset{ offset }
	{
	}

	Compiler::SymRef operator+(int64_t offset, const Compiler::SymRef& ref)
	{
		return ref + offset;
	}

	Compiler::Ref::Ref(RegRef const& ref)
		: type{ Type::Reg }
		, reg{ ref }
	{
	}

	Compiler::Ref::Ref(MemRef const& ref)
		: type{ Type::Mem }
		, mem{ ref }
	{
	}

	Compiler::Ref::Ref(Ref const& ref)
	{
		*this = ref;
	}

	Compiler::Ref::Ref(Ref&& ref)
	{
		*this = std::move(ref);
	}

	Compiler::Ref& Compiler::Ref::operator=(Ref const& ref)
	{
		type = ref.type;

		switch (type)
		{
		case Type::Reg:
			reg = ref.reg;
			break;

		case Type::Mem:
			mem = ref.mem;
			break;
		}

		return *this;
	}

	Compiler::Ref& Compiler::Ref::operator=(Ref&& ref)
	{
		type = ref.type;

		switch (type)
		{
		case Type::Reg:
			reg = std::move(ref.reg);
			break;

		case Type::Mem:
			mem = std::move(ref.mem);
			break;
		}

		return *this;
	}

	Compiler::Ref Compiler::Ref::operator+(int64_t offset) const
	{
		Ref ref = *this;

		ref.type = Type::Mem;
		ref.mem = ref.mem + offset;

		return ref;
	}

	Compiler::Ref operator+(int64_t offset, Compiler::Ref const& ref)
	{
		return ref + offset;
	}

	Compiler::Compiler()
		: m_impl{ new Compiler::Impl }
	{
	}

	Compiler::~Compiler()
	{
	}

	void Compiler::reset()
	{
		return m_impl->reset();
	}

	void Compiler::rdata(
		std::string const& name,
		uint8_t const* data,
		std::size_t size)
	{
		return m_impl->rdata(name, data, size);
	}

	void Compiler::data(
		const std::string& name,
		const uint8_t* data,
		std::size_t size)
	{
		return m_impl->data(name, data, size);
	}

	void Compiler::bss(std::string const& name, std::size_t size)
	{
		return m_impl->bss(name, size);
	}

	const ByteArray& Compiler::getCode() const
	{
		return m_impl->getCode();
	}

	Compiler::RegRef Compiler::reg(RegRef const& reg) const
	{
		return m_impl->reg(reg);
	}

	Compiler::MemRef Compiler::mem(int64_t disp) const
	{
		return m_impl->mem(disp);
	}

	Compiler::MemRef Compiler::mem(RegRef const& reg) const
	{
		return m_impl->mem(reg);
	}

	Compiler::MemRef Compiler::mem(RegRef const& index, int8_t scale) const
	{
		return m_impl->mem(index, scale);
	}

	Compiler::MemRef Compiler::mem(
		RegRef const& base,
		RegRef const& index,
		int8_t scale) const
	{
		return m_impl->mem(base, index, scale);
	}

	Compiler::SymRef Compiler::abs(std::string const& name)
	{
		return m_impl->abs(name);
	}

	Compiler::SymRef Compiler::rel(std::string const& name)
	{
		return m_impl->rel(name);
	}

	void Compiler::relocate(std::string const& name, int64_t value)
	{
		return m_impl->relocate(name, value);
	}

	void Compiler::constant(uint8_t value)
	{
		return m_impl->constant(value);
	}

	void Compiler::constant(uint16_t value)
	{
		return m_impl->constant(value);
	}

	void Compiler::constant(uint32_t value)
	{
		return m_impl->constant(value);
	}

	void Compiler::constant(uint64_t value)
	{
		return m_impl->constant(value);
	}

	void Compiler::constant(double value)
	{
		return m_impl->constant(value);
	}

	void Compiler::add(Ref const& src, Ref const& dst)
	{
		return m_impl->add(src, dst);
	}

	void Compiler::addb(uint8_t imm, Ref const& dst)
	{
		return m_impl->addb(imm, dst);
	}

	void Compiler::addw(uint16_t imm, Ref const& dst)
	{
		return m_impl->addw(imm, dst);
	}

	void Compiler::addl(uint32_t imm, Ref const& dst)
	{
		return m_impl->addl(imm, dst);
	}

	void Compiler::addq(uint64_t imm, Ref const& dst)
	{
		return m_impl->addq(imm, dst);
	}

	void Compiler::call(int32_t disp)
	{
		return m_impl->call(disp);
	}

	void Compiler::callw(int16_t disp)
	{
		return m_impl->callw(disp);
	}

	void Compiler::callq(int32_t disp)
	{
		return m_impl->callq(disp);
	}

	void Compiler::call(Ref const& ref)
	{
		return m_impl->call(ref);
	}

	void Compiler::callw(Ref const& ref)
	{
		return m_impl->callw(ref);
	}

	void Compiler::callq(Ref const& ref)
	{
		return m_impl->callq(ref);
	}

	void Compiler::lcall(Ref const& ref)
	{
		return m_impl->lcall(ref);
	}

	void Compiler::lcallw(Ref const& ref)
	{
		return m_impl->lcallw(ref);
	}

	void Compiler::lcalll(Ref const& ref)
	{
		return m_impl->lcalll(ref);
	}

	void Compiler::call(SymRef const& ref)
	{
		return m_impl->call(ref);
	}

	void Compiler::lcall(SymRef const& ref)
	{
		return m_impl->lcall(ref);
	}

	void Compiler::enter(uint16_t imm16, uint8_t imm8)
	{
		return m_impl->enter(imm16, imm8);
	}

	void Compiler::enterw(uint16_t imm16, uint8_t imm8)
	{
		return m_impl->enterw(imm16, imm8);
	}

	void Compiler::enterq(uint16_t imm16, uint8_t imm8)
	{
		return m_impl->enterw(imm16, imm8);
	}

	void Compiler::lea(MemRef const& mem_ref, RegRef const& reg_ref)
	{
		return m_impl->lea(mem_ref, reg_ref);
	}

	void Compiler::lea(SymRef const& sym_ref, RegRef const& reg_ref)
	{
		return m_impl->lea(sym_ref, reg_ref);
	}

	void Compiler::leave()
	{
		return m_impl->leave();
	}

	void Compiler::leavew()
	{
		return m_impl->leavew();
	}

	void Compiler::leaveq()
	{
		return m_impl->leaveq();
	}

	void Compiler::mov(Ref const& src, Ref const& dst)
	{
		return m_impl->mov(src, dst);
	}

	void Compiler::mov(SymRef const& src, RegRef const& dst)
	{
		return m_impl->mov(src, dst);
	}

	void Compiler::mov(RegRef const& src, SymRef const& dst)
	{
		return m_impl->mov(src, dst);
	}

	void Compiler::movb(uint8_t imm, Ref const& dst)
	{
		return m_impl->movb(imm, dst);
	}

	void Compiler::movw(uint16_t imm, Ref const& dst)
	{
		return m_impl->movw(imm, dst);
	}

	void Compiler::movl(uint32_t imm, Ref const& dst)
	{
		return m_impl->movl(imm, dst);
	}

	void Compiler::movl(SymRef const& imm, Ref const& dst)
	{
		return m_impl->movl(imm, dst);
	}

	void Compiler::movq(uint64_t imm, Ref const& dst)
	{
		return m_impl->movq(imm, dst);
	}

	void Compiler::nop()
	{
		return m_impl->nop();
	}

	void Compiler::pop(RegRef const& ref)
	{
		return m_impl->pop(ref);
	}

	void Compiler::popw(MemRef const& ref)
	{
		return m_impl->popw(ref);
	}

	void Compiler::popq(MemRef const& ref)
	{
		return m_impl->popq(ref);
	}

	void Compiler::push(uint32_t imm)
	{
		return m_impl->push(imm);
	}

	void Compiler::pushw(uint16_t imm)
	{
		return m_impl->pushw(imm);
	}

	void Compiler::pushq(uint32_t imm)
	{
		return m_impl->pushq(imm);
	}

	void Compiler::push(RegRef const& ref)
	{
		return m_impl->push(ref);
	}

	void Compiler::pushw(MemRef const& ref)
	{
		return m_impl->pushw(ref);
	}

	void Compiler::pushq(MemRef const& ref)
	{
		return m_impl->pushq(ref);
	}

	void Compiler::pushw(SymRef const& ref)
	{
		return m_impl->pushw(ref);
	}

	void Compiler::pushq(SymRef const& ref)
	{
		return m_impl->pushq(ref);
	}

	void Compiler::ret(uint16_t imm)
	{
		return m_impl->ret(imm);
	}

	void Compiler::ret()
	{
		return m_impl->ret();
	}

	void Compiler::lret(uint16_t imm)
	{
		return m_impl->lret(imm);
	}

	void Compiler::lret()
	{
		return m_impl->lret();
	}

	void Compiler::sub(Ref const& src, Ref const& dst)
	{
		return m_impl->sub(src, dst);
	}

	void Compiler::subb(uint8_t imm, Ref const& dst)
	{
		return m_impl->subb(imm, dst);
	}

	void Compiler::subw(uint16_t imm, Ref const& dst)
	{
		return m_impl->subw(imm, dst);
	}

	void Compiler::subl(uint32_t imm, Ref const& dst)
	{
		return m_impl->subl(imm, dst);
	}

	void Compiler::subq(uint64_t imm, Ref const& dst)
	{
		return m_impl->subq(imm, dst);
	}

	Compiler::Impl::Imm::Imm(uint8_t value)
		: size{ Size::Byte }
		, qword{ value }
	{
	}

	Compiler::Impl::Imm::Imm(uint16_t value)
		: size{ Size::Word }
		, qword{ value }
	{
	}

	Compiler::Impl::Imm::Imm(uint32_t value)
		: size{ Size::Dword }
		, qword{ value }
	{
	}

	Compiler::Impl::Imm::Imm(uint64_t value)
		: size{ Size::Qword }
		, qword{ value }
	{
	}

	void Compiler::Impl::reset()
	{
		m_sections.clear();
		m_symbols.clear();
	}

	void Compiler::Impl::rdata(
		std::string const& name,
		uint8_t const* data,
		std::size_t size)
	{
		std::size_t offset = section(RDATA).size();
		section(RDATA).push(data, size);
		pushSymbol(name, ".rdata", offset);
	}

	void Compiler::Impl::data(
		std::string const& name,
		uint8_t const* data,
		std::size_t size)
	{
		std::size_t offset = section(DATA).size();
		section(DATA).push(data, size);
		pushSymbol(name, ".data", offset);
	}

	void Compiler::Impl::bss(std::string const& name, std::size_t size)
	{
		std::size_t offset = section(BSS).size();
		section(BSS).push(nullptr, size);
		pushSymbol(name, ".bss", offset);
	}

	const ByteArray& Compiler::Impl::getCode() const
	{
		return section(TEXT);
	}

	Compiler::RegRef Compiler::Impl::reg(RegRef const& reg) const
	{
		return reg;
	}

	Compiler::MemRef Compiler::Impl::mem(int64_t disp) const
	{
		return disp + MemRef(0, NOREG, NOREG);
	}

	Compiler::MemRef Compiler::Impl::mem(RegRef const& reg) const
	{
		return MemRef(0, NOREG, reg);
	}

	Compiler::MemRef Compiler::Impl::mem(RegRef const& index, int8_t scale) const
	{
		return MemRef(scale, index, NOREG);
	}

	Compiler::MemRef Compiler::Impl::mem(
		RegRef const& base,
		RegRef const& index,
		int8_t scale) const
	{
		return MemRef(scale, index, base);
	}

	Compiler::SymRef Compiler::Impl::abs(std::string const& name)
	{
		return SymRef(SymRef::Type::Abs, name);
	}

	Compiler::SymRef Compiler::Impl::rel(std::string const& name)
	{
		return SymRef(SymRef::Type::Rel, name);
	}

	void Compiler::Impl::relocate(std::string const& name, int64_t value)
	{
		for (auto& reloc : m_relocs)
			if (reloc.name == name)
			{
				if (reloc.type == SymRef::Type::Abs)
					*reinterpret_cast<uint32_t*>(
						section(TEXT).data() + reloc.offset) += value;
				else
					*reinterpret_cast<uint32_t*>(
						section(TEXT).data() + reloc.offset) +=
					value - reinterpret_cast<int64_t>(
						section(TEXT).data() + reloc.offset + 4);
			}
	}

	void Compiler::Impl::constant(uint8_t value)
	{
		gen(value);
	}

	void Compiler::Impl::constant(uint16_t value)
	{
		gen(value);
	}

	void Compiler::Impl::constant(uint32_t value)
	{
		gen(value);
	}

	void Compiler::Impl::constant(uint64_t value)
	{
		gen(value);
	}

	void Compiler::Impl::constant(double value)
	{
		gen(value);
	}

	void Compiler::Impl::add(Ref const& src, Ref const& dst)
	{
		instr(0x00, src, dst);
	}

	void Compiler::Impl::addb(uint8_t imm, Ref const& dst)
	{
		add(imm, dst);
	}

	void Compiler::Impl::addw(uint16_t imm, Ref const& dst)
	{
		add(imm, dst);
	}

	void Compiler::Impl::addl(uint32_t imm, Ref const& dst)
	{
		add(imm, dst);
	}

	void Compiler::Impl::addq(uint64_t imm, Ref const& dst)
	{
		add(imm, dst);
	}

	void Compiler::Impl::add(Imm const& imm, Ref const& dst)
	{
		if (dst.type == Ref::Type::Reg && dst.reg.reg == 0)
		{
			///@ make instr for this case

			uint8_t opcode = 0x04;

			if (dst.reg.size != Size::Byte)
			{
				opcode += c_opcode_field_w;
			}

			if (imm.size == Size::Word)
			{
				gen(c_operand_size_override_prefix);
			}

			genREXPrefix(-1, dst.reg.size, -1, 0);
			genb(opcode);

			if (imm.size == Size::Qword)
			{
				gen(imm.dword);
			}
			else
			{
				gen(imm);
			}
		}
		else
		{
			instr(0x80, 0, imm, dst);
		}
	}

	void Compiler::Impl::call(int32_t disp)
	{
		callq(disp);
	}

	void Compiler::Impl::callw(int16_t disp)
	{
		gen(c_operand_size_override_prefix);
		genb(0xe8);
		gen(disp);
	}

	void Compiler::Impl::callq(int32_t disp)
	{
		genb(0xe8);
		gen(disp);
	}

	void Compiler::Impl::call(const Ref& ref)
	{
		callq(ref);
	}

	void Compiler::Impl::callw(const Ref& ref)
	{
		instr_no_w(0xff, 2, Size::Word, ref);
	}

	void Compiler::Impl::callq(const Ref& ref)
	{
		instr_no_w(0xff, 2, Size::Dword, ref);
	}

	void Compiler::Impl::lcall(const Ref& ref)
	{
		lcalll(ref);
	}

	void Compiler::Impl::lcallw(const Ref& ref)
	{
		instr_no_w(0xff, 3, Size::Word, ref);
	}

	void Compiler::Impl::lcalll(const Ref& ref)
	{
		instr_no_w(0xff, 3, Size::Dword, ref);
	}

	void Compiler::Impl::call(const SymRef& ref)
	{
		if (ref.type == SymRef::Type::Rel)
		{
			call(static_cast<int32_t>(ref.offset));
		}
		else
		{
			call(MemRef(0, NOREG, NOREG) + ref.offset);
		}

		pushReloc(
			{ ref.name, ref.type, static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::lcall(const SymRef& ref)
	{
		if (ref.type == SymRef::Type::Rel)
		{
			throw std::runtime_error("far call cannot be relative");
		}

		lcall(MemRef(0, NOREG, NOREG) + ref.offset);

		pushReloc(
			{ ref.name, ref.type, static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::enter(uint16_t imm16, uint8_t imm8)
	{
		enterq(imm16, imm8);
	}

	void Compiler::Impl::enterw(uint16_t imm16, uint8_t imm8)
	{
		genb(c_operand_size_override_prefix);
		enterq(imm16, imm8);
	}

	void Compiler::Impl::enterq(uint16_t imm16, uint8_t imm8)
	{
		genb(0xc8);
		gen(imm16);
		gen(imm8);
	}

	void Compiler::Impl::lea(const MemRef& mem_ref, const RegRef& reg_ref)
	{
		instr_no_w(0x8d, reg_ref.reg, reg_ref.size, mem_ref);
	}

	void Compiler::Impl::lea(const SymRef& sym_ref, const RegRef& reg_ref)
	{
		lea(MemRef(0, NOREG, sym_ref.type == SymRef::Type::Rel ? RIP : NOREG) +
			sym_ref.offset,
			reg_ref);

		pushReloc({ sym_ref.name,
				   sym_ref.type,
				   static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::leave()
	{
		leaveq();
	}

	void Compiler::Impl::leavew()
	{
		genb(c_operand_size_override_prefix);
		leaveq();
	}

	void Compiler::Impl::leaveq()
	{
		genb(0xc9);
	}

	void Compiler::Impl::mov(const Ref& src, const Ref& dst)
	{
		if ((src.type == Ref::Type::Reg && src.reg.reg == 0 &&
			dst.type == Ref::Type::Mem && dst.mem.base == NOREG &&
			dst.mem.index == NOREG && !isDword(dst.mem.disp)) ||
			(dst.type == Ref::Type::Reg && dst.reg.reg == 0 &&
				src.type == Ref::Type::Mem && src.mem.base == NOREG &&
				src.mem.index == NOREG && !isDword(src.mem.disp)))
		{
			instr(0xa0, dst, src);
		}
		else
		{
			instr(0x88, src, dst);
		}
	}

	void Compiler::Impl::mov(const SymRef& src, const RegRef& dst)
	{
		mov(MemRef(0, NOREG, src.type == SymRef::Type::Rel ? RIP : NOREG) +
			src.offset,
			dst);
		pushReloc(
			{ src.name, src.type, static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::mov(const RegRef& src, const SymRef& dst)
	{
		mov(src,
			MemRef(0, NOREG, dst.type == SymRef::Type::Rel ? RIP : NOREG) +
			dst.offset);
		pushReloc(
			{ dst.name, dst.type, static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::movb(uint8_t imm, const Ref& dst)
	{
		mov(imm, dst);
	}

	void Compiler::Impl::movw(uint16_t imm, const Ref& dst)
	{
		mov(imm, dst);
	}

	void Compiler::Impl::movl(uint32_t imm, const Ref& dst)
	{
		mov(imm, dst);
	}

	void Compiler::Impl::movl(const SymRef& imm, const Ref& dst)
	{
		mov(static_cast<uint32_t>(imm.offset), dst);
		pushReloc(
			{ imm.name, imm.type, static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::movq(uint64_t imm, const Ref& dst)
	{
		mov(imm, dst);
	}

	void Compiler::Impl::mov(const Imm& imm, const Ref& dst)
	{
		if (dst.type == Ref::Type::Mem ||
			(dst.reg.size == Size::Qword && isDword(imm.qword)))
		{
			instr(0xc6, 0, imm, dst);
		}
		else
		{
			if (imm.size == Size::Word)
			{
				gen(c_operand_size_override_prefix);
			}

			genREXPrefix(-1, Size::None, -1, dst.reg.reg);
			genb(
				(dst.reg.size == Size::Byte ? 0xb0 : 0xb8) +
				(dst.reg.reg & c_x86_mask));
			gen(imm);
		}
	}

	void Compiler::Impl::nop()
	{
		genb(0x90);
	}

	void Compiler::Impl::pop(const RegRef& ref)
	{
		if (ref.size == Size::Word)
		{
			gen(c_operand_size_override_prefix);
		}

		genb(0x58 + (ref.reg & c_x86_mask));
	}

	void Compiler::Impl::popw(const MemRef& ref)
	{
		instr_no_w(0x8f, 0, Size::Word, ref);
	}

	void Compiler::Impl::popq(const MemRef& ref)
	{
		instr_no_w(0x8f, 0, Size::Dword, ref);
	}

	void Compiler::Impl::push(uint32_t imm)
	{
		pushq(imm);
	}

	void Compiler::Impl::pushw(uint16_t imm)
	{
		push(imm);
	}

	void Compiler::Impl::pushq(uint32_t imm)
	{
		push(imm);
	}

	void Compiler::Impl::push(const RegRef& ref)
	{
		if (ref.size == Size::Word)
		{
			gen(c_operand_size_override_prefix);
		}

		genb(0x50 + (ref.reg & c_x86_mask));
	}

	void Compiler::Impl::pushw(const MemRef& ref)
	{
		instr_no_w(0xff, 6, Size::Word, ref);
	}

	void Compiler::Impl::pushq(const MemRef& ref)
	{
		instr_no_w(0xff, 6, Size::Dword, ref);
	}

	void Compiler::Impl::pushw(const SymRef& ref)
	{
		pushw(
			MemRef(0, NOREG, ref.type == SymRef::Type::Rel ? RIP : NOREG) +
			ref.offset);
		pushReloc(
			{ ref.name, ref.type, static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::pushq(const SymRef& ref)
	{
		pushq(
			MemRef(0, NOREG, ref.type == SymRef::Type::Rel ? RIP : NOREG) +
			ref.offset);
		pushReloc(
			{ ref.name, ref.type, static_cast<int64_t>(sectionSize(TEXT) - 4) });
	}

	void Compiler::Impl::push(const Imm& imm)
	{
		if (imm.size == Size::Word)
		{
			gen(c_operand_size_override_prefix);
		}

		if (isByte(imm.dword))
		{
			genb(0x6a);
			gen(imm.byte);
		}
		else
		{
			genb(0x68);

			if (imm.size == Size::Word)
			{
				gen(imm.word);
			}
			else
			{
				gen(imm.dword);
			}
		}
	}

	void Compiler::Impl::ret(uint16_t imm)
	{
		genb(0xc2);
		gen(imm);
	}

	void Compiler::Impl::ret()
	{
		genb(0xc3);
	}

	void Compiler::Impl::lret(uint16_t imm)
	{
		genb(0xca);
		gen(imm);
	}

	void Compiler::Impl::lret()
	{
		genb(0xcb);
	}

	void Compiler::Impl::sub(const Ref& src, const Ref& dst)
	{
		instr(0x28, src, dst);
	}

	void Compiler::Impl::subb(uint8_t imm, const Ref& dst)
	{
		sub(imm, dst);
	}

	void Compiler::Impl::subw(uint16_t imm, const Ref& dst)
	{
		sub(imm, dst);
	}

	void Compiler::Impl::subl(uint32_t imm, const Ref& dst)
	{
		sub(imm, dst);
	}

	void Compiler::Impl::subq(uint64_t imm, const Ref& dst)
	{
		sub(imm, dst);
	}

	void Compiler::Impl::sub(const Imm& imm, const Ref& dst)
	{
		if (dst.type == Ref::Type::Reg && dst.reg.reg == 0)
		{
			///@ make instr for this case

			uint8_t opcode = 0x2c;

			if (dst.reg.size != Size::Byte)
			{
				opcode += c_opcode_field_w;
			}

			if (imm.size == Size::Word)
			{
				gen(c_operand_size_override_prefix);
			}

			genREXPrefix(-1, dst.reg.size, -1, 0);
			genb(opcode);

			if (imm.size == Size::Qword)
			{
				gen(imm.dword);
			}
			else
			{
				gen(imm);
			}
		}
		else
		{
			instr(0x80, 5, imm, dst);
		}
	}

	void Compiler::Impl::instr(uint8_t opcode, const Ref& src, const Ref& dst)
	{
		RegRef reg_ref = src.type == Ref::Type::Reg ? src.reg : dst.reg;
		Ref rm_ref = src.type == Ref::Type::Reg ? dst : src;

		if (dst.type == Ref::Type::Reg && src.type != Ref::Type::Reg)
		{
			opcode += c_opcode_field_d;
		}

		instr(opcode, reg_ref.reg, reg_ref.size, rm_ref);
	}

	void Compiler::Impl::instr(
		uint8_t opcode,
		int8_t reg,
		Size size,
		const Ref& rm_ref)
	{
		if (size != Size::Byte)
		{
			opcode += c_opcode_field_w;
		}

		instr_no_w(opcode, reg, size, rm_ref);
	}

	void Compiler::Impl::instr_no_w(
		uint8_t opcode,
		int8_t reg,
		Size size,
		const Ref& rm_ref)
	{
		if (rm_ref.type == Ref::Type::Mem &&
			((rm_ref.mem.base != NOREG && rm_ref.mem.base.size != Size::Qword) ||
				(rm_ref.mem.index != NOREG && rm_ref.mem.index.size != Size::Qword)))
		{
			gen(c_address_size_override_prefix);
		}

		if (size == Size::Word)
		{
			gen(c_operand_size_override_prefix);
		}

		int8_t index = rm_ref.type == Ref::Type::Mem ? rm_ref.mem.index.reg : -1;
		int8_t base =
			rm_ref.type == Ref::Type::Mem ? rm_ref.mem.base.reg : rm_ref.reg.reg;

		genREXPrefix(reg, size, index, base);
		gen(opcode);
		genRef(reg, rm_ref);
	}

	void Compiler::Impl::instr(
		uint8_t opcode,
		int8_t ext,
		const Imm& imm,
		const Ref& dst)
	{
		instr(opcode, ext, imm.size, dst);

		if (imm.size == Size::Qword)
		{
			gen(imm.dword);
		}
		else
		{
			gen(imm);
		}
	}

	void Compiler::Impl::genREXPrefix(
		const int8_t& reg,
		Size size,
		const int8_t& index,
		const int8_t& base)
	{
		uint8_t rex = c_rex_field_w * (size == Size::Qword) +
			c_rex_field_b * (base > c_x86_mask) +
			c_rex_field_x * (index > c_x86_mask) +
			c_rex_field_r * (reg > c_x86_mask);

		if (rex)
		{
			genb(c_rex + rex);
		}
	}

	void Compiler::Impl::genRef(int8_t reg, const Ref& ref)
	{
		if (ref.type == Ref::Type::Reg)
		{
			genRef(reg, ref.reg);
		}
		else
		{
			genRef(reg, ref.mem);
		}
	}

	void Compiler::Impl::genRef(int8_t reg, const RegRef& reg_ref)
	{
		genCompositeByte(c_mod_reg, reg & c_x86_mask, reg_ref.reg & c_x86_mask);
	}

	void Compiler::Impl::genRef(int8_t reg, const MemRef& mem_ref)
	{
		if (!isDword(mem_ref.disp))
		{
			gen(mem_ref.disp);
			return;
		}

		uint8_t mod;
		uint8_t rm = mem_ref.base.reg & c_x86_mask;

		if ((mem_ref.disp == 0 && (mem_ref.base.reg & c_x86_mask) != 5) ||
			(mem_ref.scale && mem_ref.base == NOREG))
		{
			mod = c_mod_disp0;
		}
		else if (isByte(mem_ref.disp))
		{
			mod = c_mod_disp8;
		}
		else
		{
			mod = c_mod_disp32;
		}

		if (mem_ref.base == NOREG && mem_ref.index == NOREG)
		{
			mod = c_mod_disp0;
			rm = 4;
		}
		else if (mem_ref.scale)
		{
			rm = 4;
		}

		///@ not optimal
		if (mem_ref.base == RIP)
		{
			mod = c_mod_disp0;
			rm = 5;
		}

		genCompositeByte(mod, reg & c_x86_mask, rm);
		genSIB(mem_ref);

		if (mem_ref.disp_specified || (mem_ref.base.reg & c_x86_mask) == 5)
		{
			if (isByte(mem_ref.disp) && mem_ref.base != NOREG &&
				mem_ref.base != RIP)
			{
				gen(static_cast<uint8_t>(mem_ref.disp));
			}
			else
			{
				gen(static_cast<uint32_t>(mem_ref.disp));
			}
		}
	}

	void Compiler::Impl::genSIB(const MemRef& mem_ref)
	{
		int8_t scale = -1;
		uint8_t index = mem_ref.index.reg & c_x86_mask;
		uint8_t base = mem_ref.base.reg & c_x86_mask;

		if (mem_ref.scale)
		{
			if (mem_ref.index.reg == 4)
			{
				throw std::runtime_error("cannot index by %esp in SIB");
			}

			scale = mem_ref.scale;

			if (mem_ref.base == NOREG)
			{
				base = 5;
			}
		}
		else if (mem_ref.base == NOREG && mem_ref.index == NOREG)
		{
			scale = 0;
			index = 4;
			base = 5;
		}
		else if ((mem_ref.base.reg & c_x86_mask) == 4)
		{
			scale = 0;
			index = 4;
		}

		if (scale >= 0)
		{
			genCompositeByte(static_cast<uint8_t>(log2(scale)), index, base);
		}
	}

	void Compiler::Impl::genCompositeByte(uint8_t a, uint8_t b, uint8_t c)
	{
		gen(static_cast<uint8_t>((a << 6) + (b << 3) + c));
	}

	void Compiler::Impl::genb(uint8_t value)
	{
		gen(value);
	}

	void Compiler::Impl::genw(uint16_t value)
	{
		gen(value);
	}

	void Compiler::Impl::genl(uint32_t value)
	{
		gen(value);
	}

	void Compiler::Impl::genq(uint64_t value)
	{
		gen(value);
	}

	const ByteArray& Compiler::Impl::section(SectionID id) const
	{
		if (!isSectionDefined(id))
		{
			static const char* section_names[] = {
				"", "TEXT", "DATA", "BSS", "RDATA", "EDATA", "IDATA", "RELOC",
			};

			throw std::runtime_error(
				"section " + std::string(section_names[id]) + " is not defined");
		}

		return m_sections.at(id);
	}

	ByteArray& Compiler::Impl::section(SectionID id)
	{
		return m_sections[id];
	}

	bool Compiler::Impl::isSectionDefined(SectionID id) const
	{
		return m_sections.find(id) != m_sections.end();
	}

	std::size_t Compiler::Impl::sectionSize(SectionID id) const
	{
		return isSectionDefined(id) ? section(id).size() : 0;
	}

	bool Compiler::Impl::isSymbolDefined(const std::string& name) const
	{
		return m_symbols.find(name) != m_symbols.end();
	}

	void Compiler::Impl::pushSymbol(
		const std::string& name,
		const std::string& base_symbol,
		std::size_t offset)
	{
		if (isSymbolDefined(name))
			throw std::runtime_error("symbol '" + name + "' is already defined");

		m_symbols[name] = Symbol{ base_symbol, offset };
	}

	void Compiler::Impl::pushReloc(const Compiler::Impl::Reloc& reloc)
	{
		m_relocs.emplace_back(reloc);
	}

} // namespace x86_64
