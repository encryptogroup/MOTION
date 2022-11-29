#pragma once

#include <iterator>


//==================================================================================================
template<typename T>
class IntrusiveListItem
{
	template<typename X> friend class IntrusiveList;

public:
	class Iterator
	{
		template<typename X> friend class IntrusiveList;

	public:
		using value_type = T;
		using pointer = T*;
		using reference = T&;
		using difference_type = ptrdiff_t;
		using iterator_category = std::bidirectional_iterator_tag;

		explicit Iterator(IntrusiveListItem *cur) :
			m_cur{cur} {}

		T* operator -> () { return static_cast<T*>(m_cur); }
		T& operator * () { return static_cast<T&>(*m_cur); }

		Iterator& operator ++ ()
		{
			m_cur = m_cur->m_next;
			return *this;
		}

		Iterator& operator -- ()
		{
			m_cur = m_cur->m_prev;
			return *this;
		}

		friend bool operator == (Iterator a, Iterator b) { return a.m_cur == b.m_cur; }
		friend bool operator != (Iterator a, Iterator b) { return a.m_cur != b.m_cur; }

	private:
		IntrusiveListItem *m_cur;
	};

	class ConstIterator
	{
		template<typename X> friend class IntrusiveList;

	public:
		using value_type = T;
		using pointer = T const*;
		using reference = T const&;
		using difference_type = ptrdiff_t;
		using iterator_category = std::bidirectional_iterator_tag;

		explicit ConstIterator(IntrusiveListItem const *cur) :
			m_cur{cur} {}

		T const* operator -> () { return static_cast<T const*>(m_cur); }
		T const& operator * () const { return static_cast<T const&>(*m_cur); }

		ConstIterator& operator ++ ()
		{
			m_cur = m_cur->m_next;
			return *this;
		}

		ConstIterator& operator -- ()
		{
			m_cur = m_cur->m_prev;
			return *this;
		}

		friend bool operator == (ConstIterator a, ConstIterator b) { return a.m_cur == b.m_cur; }
		friend bool operator != (ConstIterator a, ConstIterator b) { return a.m_cur != b.m_cur; }

	private:
		IntrusiveListItem const *m_cur;
	};

	IntrusiveListItem() :
		m_next{nullptr},
		m_prev{nullptr} {}

	Iterator iterator() { return Iterator(this); }
	ConstIterator const_iterator() const { return ConstIterator(this); }

	// Should not use!
	IntrusiveListItem* next() { return m_next; }

private:
	IntrusiveListItem *m_next;
	IntrusiveListItem *m_prev;
};


template<typename T>
class IntrusiveList
{
public:
	using ListItem = IntrusiveListItem<T>;
	using iterator = typename ListItem::Iterator;
	using const_iterator = typename ListItem::ConstIterator;

	IntrusiveList() :
		m_size{0}
	{
		m_sentinel.m_next = &m_sentinel;
		m_sentinel.m_prev = &m_sentinel;
	}

	// We cannot copy an intrusive list because the first and the last node
	// store a pointer to rhs.m_sentinel. Thus, these pointers need to be
	// adjusted to point to this.m_sentinel.
	IntrusiveList(IntrusiveList const &rhs) = delete;

	// TODO This code may be wrong. I got a segfault, but am not sure if it
	//      originated here.
	/*IntrusiveList(IntrusiveList &&rhs) :
		m_sentinel{rhs.m_sentinel},
		m_size{rhs.m_size}
	{
		m_sentinel.m_prev->m_next = &m_sentinel;
		m_sentinel.m_next->m_prev = &m_sentinel;

		rhs.m_sentinel.m_next = &rhs.m_sentinel;
		rhs.m_sentinel.m_prev = &rhs.m_sentinel;
	}*/

	void insert(ListItem *pos, ListItem *item)
	{
		item->m_next = pos;
		item->m_prev = pos->m_prev;
		pos->m_prev->m_next = item;
		pos->m_prev = item;

		++m_size;
	}

	void insert(iterator pos, ListItem *item)
	{
		insert(pos.m_cur, item);
	}

	T* erase(ListItem *item)
	{
		item->m_prev->m_next = item->m_next;
		item->m_next->m_prev = item->prev;

		T* next = static_cast<T*>(item->m_next);
		item->m_next = nullptr;
		item->m_prev = nullptr;

		--m_size;

		return next;
	}

	iterator* erase(iterator it)
	{
		return erase(it.m_cur)->iterator();
	}

	iterator begin() { return iterator{m_sentinel.m_next}; }
	iterator end() { return iterator{&m_sentinel}; }

	const_iterator begin() const { return const_iterator{m_sentinel.m_next}; }
	const_iterator end() const { return const_iterator{&m_sentinel}; }

	size_t size() const { return m_size; }

private:
	ListItem m_sentinel;
	size_t m_size;
};
