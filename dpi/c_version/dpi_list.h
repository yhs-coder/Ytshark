#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// 定义链表节点
typedef struct dpi_list_node
{
    void* data;
    struct dpi_list_node* prev;
    struct dpi_list_node* next;
}dpi_list_node;

// 链表的定义
typedef struct dpi_list
{
    uint32_t size;              // 链表节点数
    dpi_list_node sentinal;    // 哨兵节点
}dpi_list;

// 链表接口
dpi_list* dpi_list_create();                    // 创建一个链表
int dpi_list_append(dpi_list* list, void* data);// 将数据尾插进链表
void dpi_list_destroy(dpi_list* list);          // 释放链表    
