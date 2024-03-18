#include "dpi_list.h"


// 创建一个链表
dpi_list* dpi_list_create()
{
    dpi_list* list = (dpi_list*)malloc(sizeof(dpi_list));
    if (list == NULL)
    {
        fprintf(stderr, "malloc error\n");
        return NULL;
    }
    memset(list, 0, sizeof(dpi_list));
    // 哨兵节点的prev和next指向自身
    list->sentinal.prev = &list->sentinal;
    list->sentinal.next = &list->sentinal;
    return list;
}

// 数据尾插到链表
int dpi_list_append(dpi_list* list, void* data)
{
    dpi_list_node* node = (dpi_list_node*)malloc(sizeof(dpi_list_node));
    if (node == NULL)
        return -1;
    node->data = data;
    list->size++;
    // 指向链表最后一个节点
    dpi_list_node* last_node = list->sentinal.prev;
    // 最后一个节点的next指向新增节点
    last_node->next = node;
    // 新增节点的next指向哨兵节点
    node->next = &list->sentinal;
    // 新增节点的prev指向最后一个节点
    node->prev = last_node;
    list->sentinal.prev = node;
    return 0;
}

  // 释放链表    
void dpi_list_destroy(dpi_list* list)
{
    dpi_list_node* cur = list->sentinal.next;
    while (cur != &list->sentinal)
    {
        if (cur->data)
            // 释放每个节点的数据区域
            free(cur->data);
        
        dpi_list_node* tmp = cur;
        cur = cur->next;
        // 释放每个节点的内存
        free(tmp);
        
    }
    // 释放链表
    free(list);
}        
